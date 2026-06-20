"""
mod_headers.py — Security Headers & Configuration Audit module.

Covers:
  • Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
  • Dangerous header values (Server version disclosure, X-Powered-By)
  • Cookie security flags (HttpOnly, Secure, SameSite)
  • CORS misconfiguration (Access-Control-Allow-Origin: *)
  • Information disclosure via Server / X-Powered-By headers
"""

import re
import logging
from typing import Any, Dict, List

from my_scan.modules.base import BaseModule, HIGH, MEDIUM, LOW

logger = logging.getLogger("mod_headers")


class HeadersModule(BaseModule):
    name        = "headers"
    description = "Audits HTTP response headers for security misconfigurations"

    # Headers that MUST be present
    REQUIRED_HEADERS = {
        "content-security-policy": (
            "Missing Content-Security-Policy header",
            "CSP prevents XSS and data injection attacks",
            MEDIUM,
        ),
        "x-frame-options": (
            "Missing X-Frame-Options header",
            "Without this header, the site is vulnerable to Clickjacking",
            MEDIUM,
        ),
        "x-content-type-options": (
            "Missing X-Content-Type-Options header",
            "MIME-type sniffing can be exploited for XSS",
            LOW,
        ),
        "strict-transport-security": (
            "Missing Strict-Transport-Security (HSTS) header",
            "HSTS prevents SSL-stripping attacks",
            MEDIUM,
        ),
        "referrer-policy": (
            "Missing Referrer-Policy header",
            "Referrer leakage can expose sensitive URL paths",
            LOW,
        ),
        "permissions-policy": (
            "Missing Permissions-Policy header",
            "Browser features (camera, geolocation) are unrestricted",
            LOW,
        ),
    }

    # Headers that should NOT be present (information disclosure)
    DANGEROUS_HEADERS = {
        "server": (
            "Server version disclosed in response",
            HIGH,
        ),
        "x-powered-by": (
            "Technology stack disclosed via X-Powered-By header",
            MEDIUM,
        ),
        "x-aspnet-version": (
            "ASP.NET version disclosed",
            MEDIUM,
        ),
        "x-aspnetmvc-version": (
            "ASP.NET MVC version disclosed",
            MEDIUM,
        ),
    }

    # Patterns indicating dangerous server header values
    VERSION_DISCLOSURE_PATTERN = re.compile(
        r"(apache|nginx|iis|lighttpd|jetty|tomcat|jboss|weblogic|websphere)[/\s][\d.]+",
        re.IGNORECASE,
    )

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        resp = await self._send(entrypoint)
        if resp is None:
            return findings

        try:
            body    = await resp.text()
            status  = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookies = resp.cookies
        finally:
            resp.release()

        # 1. Missing security headers
        for header_name, (vuln_name, explanation, severity) in self.REQUIRED_HEADERS.items():
            if header_name not in headers:
                findings.append(self._make_finding(
                    vulnerability=vuln_name,
                    vuln_id="missing_header",
                    severity=severity,
                    url=entrypoint["url"],
                    method=entrypoint.get("method", "GET"),
                    parameter="(response header)",
                    payload="",
                    evidence=explanation,
                ))

        # 2. Information disclosure in response headers
        for header_name, (vuln_name, severity) in self.DANGEROUS_HEADERS.items():
            if header_name in headers:
                val = headers[header_name]
                # For Server header, only flag if it contains version info
                if header_name == "server" and not self.VERSION_DISCLOSURE_PATTERN.search(val):
                    continue
                findings.append(self._make_finding(
                    vulnerability=vuln_name,
                    vuln_id="info_disclosure",
                    severity=severity,
                    url=entrypoint["url"],
                    method=entrypoint.get("method", "GET"),
                    parameter=f"Header: {header_name}",
                    payload="",
                    evidence=f"Header value: '{val}'",
                ))

        # 3. CORS misconfiguration
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            findings.append(self._make_finding(
                vulnerability="CORS Misconfiguration (Wildcard Origin)",
                vuln_id="cors",
                severity=HIGH,
                url=entrypoint["url"],
                method=entrypoint.get("method", "GET"),
                parameter="Access-Control-Allow-Origin",
                payload="",
                evidence="Server allows any origin (Access-Control-Allow-Origin: *)",
            ))

        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(self._make_finding(
                vulnerability="CORS Misconfiguration (Wildcard + Credentials)",
                vuln_id="cors",
                severity=HIGH,
                url=entrypoint["url"],
                method=entrypoint.get("method", "GET"),
                parameter="Access-Control-Allow-Credentials",
                payload="",
                evidence="Wildcard origin with credentials=true is a critical CORS misconfiguration",
            ))

        # 4. Cookie security flags
        for cookie_name, cookie in cookies.items():
            issues = []
            morsel = cookie
            if not morsel.get("httponly"):
                issues.append("missing HttpOnly flag")
            if not morsel.get("secure"):
                issues.append("missing Secure flag")
            if not morsel.get("samesite"):
                issues.append("missing SameSite attribute")

            if issues:
                findings.append(self._make_finding(
                    vulnerability=f"Insecure Cookie: {cookie_name}",
                    vuln_id="insecure_cookie",
                    severity=MEDIUM,
                    url=entrypoint["url"],
                    method=entrypoint.get("method", "GET"),
                    parameter=f"Cookie: {cookie_name}",
                    payload="",
                    evidence=f"Cookie has: {', '.join(issues)}",
                ))

        return findings
