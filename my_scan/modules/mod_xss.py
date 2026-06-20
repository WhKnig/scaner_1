"""
mod_xss.py — Cross-Site Scripting detection module.

Covers:
  • Reflected XSS     (payload echoed unescaped in response body)
  • Attribute XSS     (payload injected into HTML attribute context)
  • DOM-based hints   (payload injected into script context)
"""

import html
import re
import logging
from typing import Any, Dict, List

from my_scan.modules.base import BaseModule, HIGH, MEDIUM

logger = logging.getLogger("mod_xss")

# ── Payloads ─────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    # Canonical script-tag
    "<script>alert(1)</script>",
    # Attribute-break + script
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # Event handlers
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<details open ontoggle=alert(1)>',
    # javascript: URI
    'javascript:alert(1)',
    # HTML5 vectors
    '<video src=1 onerror=alert(1)>',
    '<audio src=1 onerror=alert(1)>',
    # Template / expression injection hints
    '{{7*7}}',
    '${7*7}',
    '<%=7*7%>',
]

# Patterns that confirm unescaped reflection
REFLECT_PATTERNS = [
    re.compile(r"<script[^>]*>alert\(1\)</script>", re.IGNORECASE),
    re.compile(r"onerror=alert\(1\)", re.IGNORECASE),
    re.compile(r"onload=alert\(1\)", re.IGNORECASE),
    re.compile(r"onfocus=alert\(1\)", re.IGNORECASE),
    re.compile(r"ontoggle=alert\(1\)", re.IGNORECASE),
    re.compile(r"<svg[^>]*onload", re.IGNORECASE),
]

# Patterns confirming SSTI-style template evaluation
SSTI_EVAL_PATTERN = re.compile(r"\b49\b")   # 7*7 == 49


class XSSModule(BaseModule):
    name        = "xss"
    description = "Detects Reflected XSS, Attribute XSS, and basic SSTI signals"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        params = self._all_params(entrypoint)

        if not params:
            return findings

        for param_name in params:
            for payload in XSS_PAYLOADS:
                ep   = self._inject_param(entrypoint, param_name, payload)
                resp = await self._send(ep)
                if resp is None:
                    continue
                try:
                    body   = await resp.text()
                    status = resp.status
                finally:
                    resp.release()

                # --- Reflected XSS check ---
                # Payload must appear in body AND not be HTML-escaped
                if payload in body:
                    escaped = html.escape(payload)
                    if escaped not in body:
                        # Confirm it's in a dangerous context
                        if any(p.search(body) for p in REFLECT_PATTERNS) or payload in body:
                            findings.append(self._make_finding(
                                vulnerability="Cross-Site Scripting (Reflected XSS)",
                                vuln_id="xss",
                                severity=HIGH,
                                url=entrypoint["url"],
                                method=entrypoint.get("method", "GET"),
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Unescaped payload reflected in response body",
                            ))
                            break  # confirmed for this param

                # --- SSTI evaluation signal ({{7*7}} → 49 in body) ---
                if payload in ("{{7*7}}", "${7*7}", "<%=7*7%>") and SSTI_EVAL_PATTERN.search(body):
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

        return findings

    # ------------------------------------------------------------------
    def _all_params(self, ep: Dict[str, Any]) -> List[str]:
        names: List[str] = []
        if ep.get("params"):
            names += list(ep["params"].keys())
        body = ep.get("body", "") or ""
        if body:
            import json as _json
            from urllib.parse import parse_qs as _pqs
            try:
                bd = _json.loads(body)
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
