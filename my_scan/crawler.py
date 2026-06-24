"""
Chrome-powered BFS Crawler using Playwright.

Architecture:
  seed_url
    │
    ├─► page.goto(url) ─► wait networkidle
    │      │
    │      ├─ Intercept all network requests (XHR/Fetch) → discovered_via="xhr"
    │      ├─ Extract <a href> links → discovered_via="html_link"
    │      └─ Extract <form> inputs → discovered_via="form"
    │
    └─► BFS queue → recurse depth-limited

Outputs:
  - AppMap  (in-memory)
  - app_map.json (file)
"""

import asyncio
import json
import logging
import re
from typing import Set, List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from playwright.async_api import async_playwright, BrowserContext, Page, Request, Response
from faker import Faker

fake = Faker()

from my_scan.models import AppMap, Endpoint

logger = logging.getLogger("ChromeCrawler")


class ChromeCrawler:
    """
    Headless-Chrome BFS crawler.
    
    For each URL in the BFS queue:
      1. Navigate with Playwright → wait for network idle
      2. Capture all XHR/Fetch requests fired by the page
      3. Extract <a href> links from DOM
      4. Extract <form> definitions from DOM
      5. Add newly discovered URLs to BFS queue
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        cookies: Optional[Dict[str, str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        output_file: str = "app_map.json",
        proxy: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_netloc = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.cookies = cookies or {}
        self.auth_headers = auth_headers or {}
        self.output_file = output_file
        self.proxy = proxy

        self.app_map = AppMap()
        self.visited: Set[str] = set()
        self._xhr_captured: Set[str] = set()

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------

    async def start(self) -> AppMap:
        logger.info(f"[ChromeCrawler] Starting Chrome crawl from: {self.base_url}")
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            
            context_args = {
                "extra_http_headers": self.auth_headers,
                "ignore_https_errors": True,
                "user_agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                )
            }
            if self.proxy:
                context_args["proxy"] = {"server": self.proxy}

            context = await browser.new_context(**context_args)

            # Inject cookies into context
            if self.cookies:
                playwright_cookies = [
                    {"name": k, "value": v, "url": self.base_url}
                    for k, v in self.cookies.items()
                ]
                await context.add_cookies(playwright_cookies)

            # BFS queue: (url, depth, parent_url)
            queue: asyncio.Queue = asyncio.Queue()
            await queue.put((self.base_url, 0, None))

            pages_visited = 0

            while not queue.empty() and pages_visited < self.max_pages:
                url, depth, parent_url = await queue.get()

                # Normalise & dedup
                clean_url = self._normalise(url)
                if not clean_url or clean_url in self.visited:
                    continue
                if not self._is_same_origin(clean_url):
                    continue

                self.visited.add(clean_url)
                pages_visited += 1

                logger.info(
                    f"  [{pages_visited}/{self.max_pages}] depth={depth}  {clean_url}"
                )

                page = await context.new_page()
                try:
                    new_urls = await self._crawl_page(
                        page, context, clean_url, depth, parent_url
                    )
                    if depth < self.max_depth:
                        for nurl in new_urls:
                            if nurl not in self.visited:
                                await queue.put((nurl, depth + 1, clean_url))
                except Exception as exc:
                    logger.warning(f"  Error crawling {clean_url}: {exc}")
                finally:
                    await page.close()

            await context.close()
            await browser.close()

        logger.info(
            f"[ChromeCrawler] Done. Discovered {len(self.app_map.nodes)} endpoints."
        )
        self._save_app_map()
        return self.app_map

    # -------------------------------------------------------------------------
    # Core page crawl logic
    # -------------------------------------------------------------------------

    async def _crawl_page(
        self,
        page: Page,
        context: BrowserContext,
        url: str,
        depth: int,
        parent_url: Optional[str],
    ) -> List[str]:
        """
        Navigate to URL, intercept network, extract links + forms.
        Returns list of newly discovered navigable URLs.
        """
        xhr_requests: List[Dict[str, Any]] = []

        # ------------------------------------------------------------------
        # Network interception: capture every XHR / Fetch request the SPA makes
        # ------------------------------------------------------------------
        async def on_request(request: Request):
            try:
                resource = request.resource_type
                if resource in ("xhr", "fetch", "document"):
                    req_url = request.url
                    if not self._is_same_origin(req_url):
                        return
                    method = request.method.upper()
                    post_data = request.post_data  # may be None
                    headers = await request.all_headers()
                    xhr_requests.append(
                        {
                            "url": req_url,
                            "method": method,
                            "body": post_data,
                            "headers": headers,
                            "resource_type": resource,
                        }
                    )
            except Exception as e:
                logger.debug(f"Request interception error: {e}")

        page.on("request", lambda r: asyncio.ensure_future(on_request(r)))

        # Navigate
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=25_000)
        except Exception:
            # Fallback: domcontentloaded is usually enough for SPAs that do redirects
            try:
                resp = await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
                await asyncio.sleep(2)  # Give SPA time to settle
            except Exception as e:
                logger.warning(f"    Navigation failed for {url}: {e}")
                return []

        status = resp.status if resp else 0
        content_type = (resp.headers.get("content-type", "") if resp else "")

        # Register the navigated page itself as an endpoint
        final_url = page.url
        if not self._is_same_origin(final_url):
            logger.debug(f"    Navigated out of scope to {final_url}. Aborting crawl.")
            return []

        parsed = urlparse(final_url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        ep = Endpoint(
            url=final_url.split("?")[0],
            method="GET",
            params=params,
            response_status=status,
            content_type=content_type,
            discovered_via="seed" if depth == 0 else "html_link",
            depth=depth,
        )
        self.app_map.add_endpoint(ep)
        if parent_url:
            self.app_map.add_relation(parent_url, final_url)

        # ------------------------------------------------------------------
        # Extract navigable <a href> links from DOM
        # ------------------------------------------------------------------
        new_urls: List[str] = []
        try:
            links = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
            for href in links:
                abs_url = urljoin(final_url, href)
                clean = self._normalise(abs_url)
                if clean and self._is_same_origin(clean) and clean not in self.visited:
                    new_urls.append(clean)
        except Exception as e:
            logger.debug(f"    Link extraction error: {e}")

        # ------------------------------------------------------------------
        # Extract <form> definitions from DOM
        # ------------------------------------------------------------------
        try:
            forms = await page.eval_on_selector_all(
                "form",
                """forms => forms.map(f => ({
                    action: f.action || '',
                    method: (f.method || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                        name: i.name || i.id || '',
                        type: i.type || 'text',
                        value: i.value || ''
                    })).filter(i => i.name)
                }))""",
            )
            for form in forms:
                action = form.get("action", "")
                if not action:
                    action = final_url
                form_url = urljoin(final_url, action)
                method = form.get("method", "GET").upper()
                form_params = {i["name"]: i["value"] for i in form.get("inputs", [])}

                form_ep = Endpoint(
                    url=form_url.split("?")[0],
                    method=method,
                    params=form_params if method == "GET" else {},
                    body=urlencode(form_params) if method == "POST" else None,
                    discovered_via="form",
                    depth=depth,
                )
                self.app_map.add_endpoint(form_ep)
                self.app_map.add_relation(final_url, form_url)
                logger.debug(
                    f"    Form discovered: {method} {form_url} "
                    f"params={list(form_params.keys())}"
                )

            # ------------------------------------------------------------------
            # Auto-Form Filler: multi-pass SPA interaction to trigger XHR POSTs
            # Pass 1: click all buttons that *reveal* forms ("Create", "New", "Add", "Post", etc.)
            # Pass 2: fill revealed forms and submit them
            # Pass 3: click action buttons ("Like", "Vote", "Follow", etc.)
            # ------------------------------------------------------------------
            logger.debug("    [Auto-Filler] Starting multi-pass SPA interaction...")

            async def fill_and_submit_visible_forms() -> int:
                """Fill all currently visible forms and submit. Returns number submitted."""
                submitted = 0
                try:
                    f_forms = await page.eval_on_selector_all(
                        "form", 
                        """forms => forms.map(f => ({
                            action: f.action || '',
                            method: (f.method || 'GET').toUpperCase()
                        }))"""
                    )
                    for fidx, form_info in enumerate(f_forms):
                        try:
                            # Fill inputs in this form
                            inputs = await page.locator(f"form >> nth={fidx} >> input:not([type='hidden']):not([type='submit']):not([type='checkbox'])").element_handles()
                            for inp in inputs:
                                try:
                                    if await inp.is_visible() and await inp.is_enabled():
                                        itype = await inp.get_attribute("type") or "text"
                                        iname = (await inp.get_attribute("name") or "").lower()
                                        if itype == "password":
                                            await inp.fill(fake.password(length=12, special_chars=True))
                                        elif any(k in iname for k in ("email",)):
                                            await inp.fill(fake.email())
                                        elif any(k in iname for k in ("url", "link", "image", "src", "href")):
                                            await inp.fill(fake.image_url())
                                        elif itype == "number" or any(k in iname for k in ("age", "amount", "price", "quantity")):
                                            await inp.fill(str(fake.random_int(min=1, max=100)))
                                        elif any(k in iname for k in ("phone", "tel")):
                                            await inp.fill(fake.phone_number())
                                        elif any(k in iname for k in ("name", "first", "last", "user")):
                                            await inp.fill(fake.user_name() if "user" in iname else fake.name())
                                        else:
                                            await inp.fill(fake.word())
                                except Exception:
                                    pass

                            # Fill textareas
                            txts = await page.locator(f"form >> nth={fidx} >> textarea").element_handles()
                            for txt in txts:
                                try:
                                    if await txt.is_visible() and await txt.is_enabled():
                                        await txt.fill(fake.paragraph(nb_sentences=3))
                                except Exception:
                                    pass

                            # Click submit button inside this form
                            submit_btn = page.locator(f"form >> nth={fidx} >> button[type='submit'], form >> nth={fidx} >> input[type='submit'], form >> nth={fidx} >> button").first
                            if await submit_btn.is_visible(timeout=500) and await submit_btn.is_enabled(timeout=500):
                                await submit_btn.click(timeout=3000)
                                await asyncio.sleep(2)
                                submitted += 1
                        except Exception:
                            pass
                except Exception:
                    pass
                return submitted

            # — Pass 1: click trigger-buttons that REVEAL forms / modals —
            reveal_keywords = [
                "create", "new", "add", "post", "write", "compose",
                "submit", "send", "publish", "upload",
            ]
            try:
                all_buttons = await page.locator("button, a[role='button']").element_handles()
                for btn in all_buttons:
                    try:
                        if not (await btn.is_visible() and await btn.is_enabled()):
                            continue
                        txt = (await btn.text_content() or "").lower().strip()
                        aria = (await btn.get_attribute("aria-label") or "").lower()
                        if any(kw in txt or kw in aria for kw in reveal_keywords):
                            await btn.click(timeout=3000)
                            await asyncio.sleep(1.5)  # wait for modal/form to appear
                            # Immediately fill & submit any newly revealed forms
                            await fill_and_submit_visible_forms()
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"    Pass-1 reveal error: {e}")

            # — Pass 2: submit any remaining visible forms (e.g. pre-rendered) —
            try:
                await fill_and_submit_visible_forms()
            except Exception as e:
                logger.debug(f"    Pass-2 form submit error: {e}")

            # — Pass 3: click action buttons (Like, Vote, Follow, Heart, etc.) —
            action_keywords = [
                "like", "vote", "heart", "follow", "upvote",
                "react", "share", "retweet", "bookmark",
            ]
            try:
                action_buttons = await page.locator("button, [role='button']").element_handles()
                for btn in action_buttons:
                    try:
                        if not (await btn.is_visible() and await btn.is_enabled()):
                            continue
                        txt  = (await btn.text_content() or "").lower().strip()
                        aria = (await btn.get_attribute("aria-label") or "").lower()
                        cls  = (await btn.get_attribute("class") or "").lower()
                        if any(kw in txt or kw in aria or kw in cls for kw in action_keywords):
                            await btn.click(timeout=3000)
                            await asyncio.sleep(1)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"    Pass-3 action-click error: {e}")


        except Exception as e:
            logger.debug(f"    Form extraction/fill error: {e}")

        # ------------------------------------------------------------------
        # Process captured XHR / Fetch requests
        # ------------------------------------------------------------------
        for xhr in xhr_requests:
            xhr_url = xhr["url"]
            if xhr_url in self._xhr_captured:
                continue
            self._xhr_captured.add(xhr_url)

            p = urlparse(xhr_url)
            xhr_params = {k: v[0] for k, v in parse_qs(p.query).items()}

            xhr_ep = Endpoint(
                url=xhr_url.split("?")[0],
                method=xhr["method"],
                params=xhr_params,
                body=xhr["body"],
                headers=xhr["headers"],
                discovered_via="xhr" if xhr["resource_type"] == "xhr" else "fetch",
                depth=depth,
            )
            self.app_map.add_endpoint(xhr_ep)
            self.app_map.add_relation(final_url, xhr_url)
            logger.debug(f"    XHR captured: {xhr['method']} {xhr_url}")

        return new_urls

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _is_same_origin(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.base_netloc
        except Exception:
            return False

    def _normalise(self, url: str) -> Optional[str]:
        """Strip fragments, JavaScript pseudolinks, data URIs."""
        if not url or url.startswith(("javascript:", "mailto:", "data:", "#")):
            return None
        # Remove fragment
        return url.split("#")[0].rstrip("/") or None

    def _save_app_map(self):
        try:
            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(self.app_map.to_dict(), f, indent=2, ensure_ascii=False)
            logger.info(f"[ChromeCrawler] App map saved → {self.output_file}")
        except Exception as e:
            logger.error(f"Failed to save app_map.json: {e}")
