"""
mod_open_redirect.py — Open Redirect detection module.

Covers:
  • URL parameter redirect injection (Location header analysis)
  • Meta-refresh redirect detection in body
  • JavaScript redirect patterns in body
"""

import re
import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

from my_scan.modules.base import BaseModule, HIGH, MEDIUM

logger = logging.getLogger("mod_open_redirect")

# ── Payloads ─────────────────────────────────────────────────────────────────

# Use a clearly identifiable external domain to detect redirects
REDIRECT_DOMAIN = "evil.example.com"

REDIRECT_PAYLOADS = [
    f"https://{REDIRECT_DOMAIN}/",
    f"http://{REDIRECT_DOMAIN}/",
    f"//{REDIRECT_DOMAIN}/",
    f"/{REDIRECT_DOMAIN}/",
    f"https://{REDIRECT_DOMAIN}%2F",
    f"https://{REDIRECT_DOMAIN}%2F%2F",
    # Encoded slashes
    f"https:%2F%2F{REDIRECT_DOMAIN}/",
    # Protocol-relative
    f"//{REDIRECT_DOMAIN}/%2E%2E",
    # Null byte tricks
    f"https://{REDIRECT_DOMAIN}%00",
    f"https://{REDIRECT_DOMAIN}\r\nX-Header: injected",
    # Unicode / IDN
    f"https://evil\u2025example.com/",
    # @-trick
    f"https://legit.example.com@{REDIRECT_DOMAIN}/",
    # JavaScript
    "javascript:alert(document.domain)",
    "JaVaScRiPt:alert(1)",
]

# URL params most likely to be redirect targets
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "redirectTo",
    "return", "returnUrl", "return_url", "returnTo",
    "next", "nextUrl", "next_url",
    "url", "goto", "dest", "destination",
    "target", "redir", "ref", "referer", "referrer",
    "callback", "callbackUrl", "successUrl", "failureUrl",
    "continue", "from", "to", "forward",
]

# ── Detection patterns ────────────────────────────────────────────────────────

META_REFRESH_PATTERN = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url\s*=\s*([^\s"\']+)',
    re.IGNORECASE,
)

JS_REDIRECT_PATTERNS = [
    re.compile(r'window\.location\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'window\.location\.href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'document\.location\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
]


class OpenRedirectModule(BaseModule):
    name        = "open_redirect"
    description = "Detects Open Redirect vulnerabilities via Location header and body analysis"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Only test params that are likely redirect candidates
        all_params = self._all_params(entrypoint)
        target_params = [p for p in all_params if p.lower() in REDIRECT_PARAMS] or all_params

        if not target_params:
            return findings

        for param_name in target_params:
            for payload in REDIRECT_PAYLOADS:
                ep   = self._inject_param(entrypoint, param_name, payload)
                resp = await self._send(ep, allow_redirects=False)
                if resp is None:
                    continue
                try:
                    body    = await resp.text()
                    status  = resp.status
                    loc     = resp.headers.get("Location", "")
                finally:
                    resp.release()

                # 1. Location header points to our domain
                if loc and REDIRECT_DOMAIN in loc:
                    findings.append(self._make_finding(
                        vulnerability="Open Redirect (Location Header)",
                        vuln_id="open_redirect",
                        severity=HIGH,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Server responded with Location: {loc!r}",
                    ))
                    break

                # 2. 3xx redirect to external domain
                if status in (301, 302, 303, 307, 308) and loc:
                    parsed = urlparse(loc)
                    if parsed.netloc and parsed.netloc != urlparse(entrypoint["url"]).netloc:
                        findings.append(self._make_finding(
                            vulnerability="Open Redirect (External 3xx)",
                            vuln_id="open_redirect",
                            severity=HIGH,
                            url=entrypoint["url"],
                            method=entrypoint.get("method", "GET"),
                            parameter=param_name,
                            payload=payload,
                            evidence=f"External redirect to '{loc}'",
                        ))
                        break

                # 3. Meta-refresh redirect in body
                meta = META_REFRESH_PATTERN.search(body)
                if meta and REDIRECT_DOMAIN in meta.group(1):
                    findings.append(self._make_finding(
                        vulnerability="Open Redirect (Meta-Refresh)",
                        vuln_id="open_redirect",
                        severity=MEDIUM,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Meta-refresh redirects to '{meta.group(1)}'",
                    ))
                    break

                # 4. JavaScript redirect
                for js_pat in JS_REDIRECT_PATTERNS:
                    m = js_pat.search(body)
                    if m and REDIRECT_DOMAIN in m.group(1):
                        findings.append(self._make_finding(
                            vulnerability="Open Redirect (JavaScript)",
                            vuln_id="open_redirect",
                            severity=MEDIUM,
                            url=entrypoint["url"],
                            method=entrypoint.get("method", "GET"),
                            parameter=param_name,
                            payload=payload,
                            evidence=f"JS redirect to '{m.group(1)}'",
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
