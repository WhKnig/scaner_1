import asyncio
import logging
import json
import time
import datetime
import re
import sys
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse

from my_scan.models import ScanState, AppMap, Endpoint, Vulnerability, ScanReport, ScanState
from my_scan.session import SessionController
from my_scan.crawler import ChromeCrawler
from my_scan.attack import AttackGenerator, RequestSender, ModuleRunner
from my_scan.analyzer import ResponseAnalyzer, Classifier
from my_scan.reporter import HTMLReporter

# ─────────────────────────────────────────────────────────────────
# Logging setup — показывает цветные уровни в терминале
# ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ScanManager")

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>)\\]+", re.IGNORECASE
)


class ScanManager:
    """
    Главный координатор всех фаз сканирования.

    Параметры
    ---------
    auth_url        : URL страницы логина (опционально)
    auth_creds      : {'username': '...', 'password': '...'}
    max_depth       : глубина BFS краулера
    max_pages       : максимальное кол-во страниц на одну итерацию краула
    max_cycles      : максимальное кол-во циклов self-restart
    output_dir      : куда сохранять артефакты (по умолчанию '.')
    """

    def __init__(
        self,
        auth_url: Optional[str] = None,
        auth_creds: Optional[Dict[str, str]] = None,
        cookies: Optional[List[Dict[str, Any]]] = None,
        check_alive_url: Optional[str] = None,
        max_depth: int = 3,
        max_pages: int = 200,
        max_cycles: int = 2,
        output_dir: str = ".",
        extra_endpoints: Optional[List[Dict[str, Any]]] = None,
        proxy: Optional[str] = None,
    ):
        self.auth_url = auth_url
        self.auth_creds = auth_creds
        self.cookies = cookies
        self.check_alive_url = check_alive_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.max_cycles = max_cycles
        self.output_dir = output_dir.rstrip("/")
        self.proxy = proxy

        self.state: ScanState = ScanState.INIT
        self.session_controller = SessionController(
            auth_url=auth_url,
            auth_creds=auth_creds,
            check_alive_url=check_alive_url,
        )
        if cookies:
            for c in cookies:
                self.session_controller.cookies[c["name"]] = c["value"]
            self.session_controller.is_authenticated = True

        self.target_url: Optional[str] = None
        self.app_map: AppMap = AppMap()
        self.vulnerabilities: List[Vulnerability] = []
        self.attack_vectors_sent: int = 0
        self.scan_start: str = ""
        self.scan_end: str = ""
        self.start_ts: float = 0.0
        self.extra_endpoints: List[Dict[str, Any]] = extra_endpoints or []

        # URLs already scanned across all cycles (prevents infinite loops)
        self._scanned_seeds: Set[str] = set()

    # ─────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────

    async def start_scan(self, target: str) -> None:
        self.target_url = target
        self.start_ts = time.monotonic()
        self.scan_start = datetime.datetime.now(datetime.timezone.utc).isoformat()

        logger.info("=" * 60)
        logger.info(f"  TARGET : {target}")
        logger.info(f"  DEPTH  : {self.max_depth}   PAGES: {self.max_pages}   CYCLES: {self.max_cycles}")
        logger.info("=" * 60)

        # Ensure output dir exists
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        # Clear attack log for this run
        open(f"{self.output_dir}/attack_log.jsonl", "w").close()

        try:
            # Setup session if credentials provided
            if self.auth_url and self.auth_creds:
                logger.info("[Init] Setting up authenticated session...")
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    page = await browser.new_page()
                    success = await self.session_controller.perform_login(page)
                    await browser.close()
                if success:
                    logger.info("[Init] Successfully logged in and extracted session tokens.")
                else:
                    logger.warning("[Init] Login failed. Proceeding with unauthenticated session.")
            
            await self._run_lifecycle()
            self.state = ScanState.FINISHED
        except Exception as exc:
            self.state = ScanState.ERROR
            logger.exception(f"Fatal error in scan lifecycle: {exc}")
        finally:
            self.scan_end = datetime.datetime.now(datetime.timezone.utc).isoformat()
            duration = round(time.monotonic() - self.start_ts, 2)
            report = self._build_report(duration)
            self._save_json_report(report)
            self._generate_html_report(report)
            self._print_summary(report)

    # ─────────────────────────────────────────────────────────────
    # Main lifecycle
    # ─────────────────────────────────────────────────────────────

    async def _run_lifecycle(self) -> None:
        """
        Self-restarting scan loop:
          cycle 0: crawl seed → attack → analyse
          cycle N: crawl newly discovered URLs → attack → analyse
        """
        seeds_to_crawl = [self.target_url]
        cycle = 0

        while seeds_to_crawl and cycle < self.max_cycles:
            cycle += 1
            logger.info(f"\n{'─'*60}")
            logger.info(f"  CYCLE {cycle}/{self.max_cycles}  —  {len(seeds_to_crawl)} seed(s)")
            logger.info(f"{'─'*60}")

            # ── PHASE 1: CRAWL ──────────────────────────────────────
            self.state = ScanState.CRAWLING
            new_endpoints = await self._crawl_seeds(seeds_to_crawl)
            self._scanned_seeds.update(seeds_to_crawl)

            if not new_endpoints:
                logger.info("[Phase 1] No new endpoints discovered. Stopping cycles.")
                break

            logger.info(
                f"[Phase 1] ✓ Discovered {len(new_endpoints)} new endpoints "
                f"(total map: {len(self.app_map.nodes)})"
            )

            # ── INJECT EXTRA ENDPOINTS (first cycle only) ─────────────
            if cycle == 1 and self.extra_endpoints:
                for ep_def in self.extra_endpoints:
                    ep = Endpoint(
                        url=ep_def.get("url", ""),
                        method=ep_def.get("method", "POST").upper(),
                        params=ep_def.get("params", {}),
                        body=json.dumps(ep_def["body"]) if ep_def.get("body") else None,
                        headers=ep_def.get("headers", {}),
                        discovered_via="manual",
                        depth=0,
                    )
                    if ep.url:
                        self.app_map.add_endpoint(ep)
                        new_endpoints.append(ep)
                logger.info(
                    f"[Phase 1] + Injected {len(self.extra_endpoints)} manual endpoint(s)"
                )

            # ── PHASE 2: ATTACK ──────────────────────────────────────
            self.state = ScanState.ATTACKING
            raw_results = await self._attack_endpoints(new_endpoints)

            # ── PHASE 3: ANALYZE ─────────────────────────────────────
            self.state = ScanState.ANALYZING
            found_vulns = self._analyze_results(raw_results)
            self.vulnerabilities.extend(found_vulns)
            logger.info(
                f"[Phase 3] ✓ Found {len(found_vulns)} vulnerability(ies) this cycle"
            )

            # ── SELF-RESTART: extract new URLs from attack responses ──
            next_seeds = self._extract_new_urls_from_results(raw_results)
            seeds_to_crawl = [
                u for u in next_seeds if u not in self._scanned_seeds
            ]
            if seeds_to_crawl:
                logger.info(
                    f"[Self-Restart] {len(seeds_to_crawl)} new URL(s) queued "
                    f"for next cycle"
                )

    # ─────────────────────────────────────────────────────────────
    # Phase helpers
    # ─────────────────────────────────────────────────────────────

    async def _crawl_seeds(self, seeds: List[str]) -> List[Endpoint]:
        """Run Chrome crawler for each seed; merge results into self.app_map."""
        before = set(self.app_map.nodes.keys())
        map_file = f"{self.output_dir}/app_map.json"

        for seed in seeds:
            crawler = ChromeCrawler(
                base_url=seed,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
                cookies=self.session_controller.cookies,
                auth_headers=self.session_controller.auth_headers,
                output_file=map_file,
                proxy=self.proxy,
            )
            partial_map = await crawler.start()
            # Merge into global app_map
            for key, ep in partial_map.nodes.items():
                self.app_map.nodes[key] = ep
            for parent, children in partial_map.edges.items():
                if parent not in self.app_map.edges:
                    self.app_map.edges[parent] = set()
                self.app_map.edges[parent].update(children)

        # Persist merged map
        try:
            with open(map_file, "w", encoding="utf-8") as f:
                json.dump(self.app_map.to_dict(), f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"Could not save app_map.json: {e}")

        after = set(self.app_map.nodes.keys())
        new_keys = after - before
        return [self.app_map.nodes[k] for k in new_keys]

    async def _attack_endpoints(
        self, endpoints: List[Endpoint]
    ) -> List[Dict[str, Any]]:
        """Run both the new ModuleRunner and legacy RequestSender pipelines."""
        mini_map = AppMap()
        for ep in endpoints:
            mini_map.add_endpoint(ep)

        log_file = f"{self.output_dir}/attack_log.jsonl"

        # ── NEW: Modular engine (mod_sqli, mod_xss, mod_ssrf, …) ──────────
        logger.info("[Phase 2a] Running modular attack engine...")
        runner = ModuleRunner(
            session_controller=self.session_controller,
            log_file=log_file,
            proxy=self.proxy,
        )
        _, module_vulns = await runner.run_all(mini_map)
        if module_vulns:
            self.vulnerabilities.extend(module_vulns)
            logger.info(
                f"[Phase 2a] ✓ Modular engine found {len(module_vulns)} issue(s)"
            )
        self.attack_vectors_sent += runner.vectors_sent

        # ── LEGACY: Flat fuzzer (AttackGenerator + RequestSender) ─────────
        logger.info("[Phase 2b] Running legacy fuzzer...")
        generator = AttackGenerator()
        vectors   = generator.generate_vectors(mini_map)

        if not vectors:
            logger.info("[Phase 2b] No legacy vectors for this endpoint set.")
            return []

        logger.info(f"[Phase 2b] Sending {len(vectors)} vectors...")
        sender = RequestSender(
            session_controller=self.session_controller,
            log_file=log_file,
            proxy=self.proxy,
        )
        results = await sender.execute_queue(vectors)
        self.attack_vectors_sent += sender.vectors_sent
        return results

    def _analyze_results(
        self, raw_results: List[Dict[str, Any]]
    ) -> List[Vulnerability]:
        """Run ResponseAnalyzer + Classifier over raw results."""
        analyzer = ResponseAnalyzer()
        classifier = Classifier()
        vulns: List[Vulnerability] = []

        for res in raw_results:
            if not res:
                continue
            anomalies = analyzer.detect_anomalies(res)
            filtered = classifier.filter_false_positives(anomalies, res)
            for anomaly in filtered:
                vuln = classifier.classify(anomaly, res)
                vulns.append(vuln)
                logger.warning(
                    f"  [!] {vuln.severity.upper()} — {vuln.vulnerability_type} "
                    f"| {vuln.method} {vuln.url} | param='{vuln.parameter}' "
                    f"| payload={repr(vuln.payload)}"
                )
        return vulns

    def _extract_new_urls_from_results(
        self, raw_results: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Scan response bodies for URLs that belong to the same origin
        and haven't been crawled yet. Strips malformed URLs (backslashes etc.)
        """
        base_netloc = urlparse(self.target_url).netloc
        found: Set[str] = set()
        for res in raw_results:
            body = res.get("body", "") or ""
            for m in URL_PATTERN.finditer(body):
                url = m.group(0).rstrip(".,;)'\"")
                # Skip URLs containing backslashes or other malformed chars
                if "\\" in url or url.count("/") < 3:
                    continue
                try:
                    parsed = urlparse(url)
                    if parsed.netloc == base_netloc and parsed.scheme in ("http", "https"):
                        clean = url.split("#")[0].rstrip("/")
                        if clean and clean not in self._scanned_seeds:
                            found.add(clean)
                except ValueError:
                    pass
        return list(found)

    # ─────────────────────────────────────────────────────────────
    # Report generation
    # ─────────────────────────────────────────────────────────────

    def _build_report(self, duration: float) -> ScanReport:
        return ScanReport(
            target_url=self.target_url or "unknown",
            state=self.state.value,
            scan_start=self.scan_start,
            scan_end=self.scan_end,
            duration_seconds=duration,
            endpoints_found=len(self.app_map.nodes),
            attack_vectors_sent=self.attack_vectors_sent,
            vulnerabilities=self.vulnerabilities,
            app_map=self.app_map,
        )

    def _save_json_report(self, report: ScanReport) -> None:
        path = f"{self.output_dir}/report.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=4, ensure_ascii=False)
            logger.info(f"[Report] JSON report → {path}")
        except Exception as e:
            logger.error(f"Failed to save report.json: {e}")

    def _generate_html_report(self, report: ScanReport) -> None:
        self.state = ScanState.REPORTING
        path = f"{self.output_dir}/report.html"
        attack_log_path = f"{self.output_dir}/attack_log.jsonl"
        try:
            reporter = HTMLReporter()
            reporter.generate(
                report=report,
                attack_log_path=attack_log_path,
                output_path=path,
            )
            logger.info(f"[Report] HTML report → {path}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    def _print_summary(self, report: ScanReport) -> None:
        sev = report.to_dict().get("severity_breakdown", {})
        logger.info("\n" + "=" * 60)
        logger.info(f"  SCAN COMPLETE   ({report.duration_seconds}s)")
        logger.info(f"  Endpoints found : {report.endpoints_found}")
        logger.info(f"  Vectors sent    : {report.attack_vectors_sent}")
        logger.info(f"  Vulnerabilities : {len(report.vulnerabilities)}")
        for s, n in sev.items():
            if n:
                logger.info(f"    {s:<10}: {n}")
        logger.info("=" * 60 + "\n")


# ─────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Modular DAST Scanner")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("out_dir", nargs="?", default=".", help="Output directory")
    parser.add_argument("--auth-url", help="URL to perform login")
    parser.add_argument("--username", help="Username for login")
    parser.add_argument("--password", help="Password for login")
    parser.add_argument("--cookies", help="JSON string of cookies to use for authentication")
    parser.add_argument("--check-alive-url", help="URL to verify active session")
    parser.add_argument(
        "--extra-endpoints",
        help=(
            'JSON array of endpoint dicts to test in addition to crawled ones. '
            'Each dict: {"url":"...","method":"POST","body":{...},"params":{...}}'
        ),
    )
    parser.add_argument("--proxy", help="HTTP proxy URL, e.g., http://localhost:8080")
    parser.add_argument("--max-depth", type=int, default=3, help="Max crawling depth")
    
    args = parser.parse_args()

    auth_creds = None
    if args.username and args.password:
        auth_creds = {"username": args.username, "password": args.password}
        
    cookies = None
    if args.cookies:
        try:
            cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            logger.error("Failed to parse cookies JSON argument.")
            sys.exit(1)

    extra_endpoints = None
    if args.extra_endpoints:
        try:
            extra_endpoints = json.loads(args.extra_endpoints)
            logger.info(f"Loaded {len(extra_endpoints)} extra endpoint(s) from --extra-endpoints")
        except json.JSONDecodeError:
            logger.error("Failed to parse --extra-endpoints JSON argument.")
            sys.exit(1)

    manager = ScanManager(
        auth_url=args.auth_url,
        auth_creds=auth_creds,
        cookies=cookies,
        check_alive_url=args.check_alive_url,
        extra_endpoints=extra_endpoints,
        max_depth=args.max_depth,
        max_pages=200,
        max_cycles=2,
        output_dir=args.out_dir,
        proxy=args.proxy,
    )
    asyncio.run(manager.start_scan(args.target))


"""
ScanManager — главный оркестратор сканера.

Жизненный цикл (BPMN-схема):
  ┌─────────────────────────────────────────────────────┐
  │  INIT                                               │
  │    └─► CRAWLING: ChromeCrawler(seed_url) → AppMap   │
  │              │                                      │
  │              ▼                                      │
  │         AppMap saved → app_map.json                 │
  │              │                                      │
  │              ▼                                      │
  │  ATTACKING: AttackGenerator → vectors               │
  │    RequestSender.execute_queue() → raw_results      │
  │    (каждый вектор пишется в attack_log.jsonl)       │
  │              │                                      │
  │              ▼                                      │
  │  ANALYZING: ResponseAnalyzer + Classifier           │
  │    → List[Vulnerability]                            │
  │              │                                      │
  │  Self-restart: если в ответах атак найдены          │
  │  новые URL → добавить в очередь → CRAWLING снова    │
  │              │                                      │
  │              ▼                                      │
  │  REPORTING: HTMLReporter → report.html              │
  │              │                                      │
  │              ▼                                      │
  │  FINISHED: report.json сохранён                     │
  └─────────────────────────────────────────────────────┘
"""