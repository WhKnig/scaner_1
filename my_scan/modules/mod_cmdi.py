"""
mod_cmdi.py — OS Command Injection detection module.

Covers:
  • Direct command output reflection (root:x:0:0, uid=...)
  • Error message leakage (sh: command not found)
  • Time-based blind (sleep payloads + latency check)
"""

import re
import time
import logging
from typing import Any, Dict, List

from my_scan.modules.base import BaseModule, CRITICAL, HIGH, MEDIUM

logger = logging.getLogger("mod_cmdi")

# ── Payloads ─────────────────────────────────────────────────────────────────

CMDI_PAYLOADS = [
    # Unix — output-based
    "; id",
    "| id",
    "` id`",
    "$(id)",
    "; id #",
    "| id #",
    "; whoami",
    "| whoami",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "& whoami &",
    "&& whoami",
    "|| whoami",
    # Windows — output-based
    "& whoami",
    "| whoami /all",
    "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    # Newline / CRLF trick
    "\nid\n",
    "\r\nid\r\n",
]

TIME_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "& timeout /T 5 &",         # Windows
]

TIME_THRESHOLD_S = 4.5

# ── Detection signatures ──────────────────────────────────────────────────────

OUTPUT_PATTERNS = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"uid=\d+\(.*?\)", re.IGNORECASE),
    re.compile(r"gid=\d+\(.*?\)", re.IGNORECASE),
    re.compile(r"/bin/(bash|sh|dash)", re.IGNORECASE),
    re.compile(r"(www-data|nobody|apache|nginx|root)\s*$", re.MULTILINE),
    # Windows outputs
    re.compile(r"volume serial number is", re.IGNORECASE),
    re.compile(r"windows ip configuration", re.IGNORECASE),
    re.compile(r"Microsoft Windows \[Version", re.IGNORECASE),
    # Error leakage
    re.compile(r"sh:\s+\d+:", re.IGNORECASE),
    re.compile(r"command not found", re.IGNORECASE),
]


class CMDIModule(BaseModule):
    name        = "cmdi"
    description = "Detects OS Command Injection (output-based and time-based)"

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        params = self._all_params(entrypoint)

        if not params:
            return findings

        for param_name in params:
            # 1. Output / Error-based
            for payload in CMDI_PAYLOADS:
                ep   = self._inject_param(entrypoint, param_name, payload)
                resp = await self._send(ep)
                if resp is None:
                    continue
                try:
                    body   = await resp.text()
                    status = resp.status
                finally:
                    resp.release()


                matched = next((p for p in OUTPUT_PATTERNS if p.search(body)), None)
                if matched:
                    findings.append(self._make_finding(
                        vulnerability="OS Command Injection",
                        vuln_id="cmdi",
                        severity=CRITICAL,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Command output pattern detected: '{matched.pattern}'",
                    ))
                    break

            # 2. Time-based blind
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
                        vulnerability="OS Command Injection (Time-based Blind)",
                        vuln_id="cmdi_blind",
                        severity=HIGH,
                        url=entrypoint["url"],
                        method=entrypoint.get("method", "GET"),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Response delayed {elapsed:.2f}s after sleep payload",
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
