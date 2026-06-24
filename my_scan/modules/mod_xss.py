"""
mod_xss.py — Cross-Site Scripting detection module.

Covers:
  • Reflected XSS     (payload execution confirmed via JS hook in Playwright)
  • DOM-based hints   (payload execution confirmed via JS hook in Playwright)
  • Server-Side Template Injection (legacy string match)
"""

import html
import re
import logging
import asyncio
from typing import Any, Dict, List
import urllib.parse
import json

from playwright.async_api import async_playwright
from my_scan.modules.base import BaseModule, HIGH, MEDIUM

logger = logging.getLogger("mod_xss")

# ── Payloads ─────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    # Payload designed to trigger our specific JS hook
    "<script>window.__xss_triggered=true; console.log('XSS_TRIGGERED');</script>",
    '"><script>window.__xss_triggered=true; console.log("XSS_TRIGGERED");</script>',
    "'><script>window.__xss_triggered=true; console.log('XSS_TRIGGERED');</script>",
    '<img src=x onerror="window.__xss_triggered=true; console.log(\'XSS_TRIGGERED\')">',
    '<svg onload="window.__xss_triggered=true; console.log(\'XSS_TRIGGERED\')">',
    '<body onload="window.__xss_triggered=true; console.log(\'XSS_TRIGGERED\')">',
    '<input autofocus onfocus="window.__xss_triggered=true; console.log(\'XSS_TRIGGERED\')">',
    'javascript:window.__xss_triggered=true;console.log("XSS_TRIGGERED");',
]

SSTI_EVAL_PATTERN = re.compile(r"\b49\b")   # 7*7 == 49

class XSSModule(BaseModule):
    name        = "xss"
    description = "Detects Reflected XSS using client-side JS hooks via Headless Browser"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        params = self._all_params(entrypoint)

        if not params:
            return findings

        # 1. Playwright-based XSS Check via JS Hook
        try:
            async with async_playwright() as p:
                # Launch a lightweight browser instance
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                
                for param_name in params:
                    for payload in XSS_PAYLOADS:
                        ep = self._inject_param(entrypoint, param_name, payload)
                        page = await context.new_page()
                        
                        xss_triggered = False
                        
                        def handle_console(msg):
                            nonlocal xss_triggered
                            if "XSS_TRIGGERED" in msg.text:
                                xss_triggered = True
                                
                        page.on("console", handle_console)
                        await page.add_init_script("window.__xss_triggered = false;")
                        
                        try:
                            if ep.get("method", "GET").upper() == "GET":
                                query = urllib.parse.urlencode(ep.get("params", {}))
                                url = f"{ep['url']}?{query}" if query else ep['url']
                                await page.goto(url, wait_until="networkidle", timeout=3000)
                            else:
                                # For POST, we inject a form and submit
                                form_html = f"<form id='xssform' action='{ep['url']}' method='POST'>"
                                body_data = ep.get("body", "")
                                
                                parsed_body = {}
                                if isinstance(body_data, dict):
                                    parsed_body = body_data
                                elif isinstance(body_data, str) and body_data:
                                    try:
                                        parsed_body = json.loads(body_data)
                                    except Exception:
                                        qs = urllib.parse.parse_qs(body_data)
                                        parsed_body = {k: v[0] for k, v in qs.items()}
                                
                                for k, v in parsed_body.items():
                                    v_esc = html.escape(str(v))
                                    form_html += f"<input type='hidden' name='{k}' value='{v_esc}'>"
                                        
                                form_html += "</form><script>document.getElementById('xssform').submit();</script>"
                                await page.set_content(form_html)
                                await page.wait_for_load_state("networkidle", timeout=3000)
                        except Exception:
                            pass
                            
                        # Check variable injection as secondary verification
                        try:
                            js_val = await page.evaluate("window.__xss_triggered")
                            if js_val:
                                xss_triggered = True
                        except Exception:
                            pass
                            
                        await page.close()
                        
                        if xss_triggered:
                            findings.append(self._make_finding(
                                vulnerability="Cross-Site Scripting (Reflected XSS via JS Hook)",
                                vuln_id="xss",
                                severity=HIGH,
                                url=entrypoint["url"],
                                method=entrypoint.get("method", "GET"),
                                parameter=param_name,
                                payload=payload,
                                evidence="Client-side JS hook execution confirmed (window.__xss_triggered=true or console log)",
                            ))
                            break # Move to next param
                            
                await browser.close()
        except Exception as e:
            logger.error(f"Playwright XSS error: {e}")

        # 2. SSTI Check via traditional aiohttp
        for param_name in params:
            for payload in ("{{7*7}}", "${7*7}", "<%=7*7%>"):
                ep = self._inject_param(entrypoint, param_name, payload)
                resp = await self._send(ep)
                if resp:
                    try:
                        body = await resp.text()
                        if SSTI_EVAL_PATTERN.search(body):
                            findings.append(self._make_finding(
                                vulnerability="Server-Side Template Injection (SSTI)",
                                vuln_id="ssti",
                                severity=HIGH,
                                url=entrypoint["url"],
                                method=entrypoint.get("method", "GET"),
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Template expression '{payload}' evaluated to '49' in response",
                            ))
                            break
                    finally:
                        resp.release()

        return findings

    # ------------------------------------------------------------------
    def _all_params(self, ep: Dict[str, Any]) -> List[str]:
        names: List[str] = []
        if ep.get("params"):
            names += list(ep["params"].keys())
        body = ep.get("body", "") or ""
        if body:
            try:
                bd = json.loads(body)
                if isinstance(bd, dict):
                    names += [k for k in bd if k not in names]
            except Exception:
                pass
            try:
                for k in urllib.parse.parse_qs(body):
                    if k not in names:
                        names.append(k)
            except Exception:
                pass
        return names
