"""
Base class for all attack modules.

Each module must:
  - Define class-level `name` and `description`.
  - Implement async `run(entrypoint) -> list[Finding]`.

Finding dict schema:
    {
        "vulnerability": str,   # human-readable name
        "vuln_id":       str,   # machine-readable key (e.g. "sqli", "xss")
        "severity":      str,   # "Critical" | "High" | "Medium" | "Low"
        "url":           str,
        "method":        str,
        "parameter":     str,
        "payload":       str,
        "evidence":      str,   # what in the response triggered the finding
    }
"""

import copy
import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, parse_qs

import aiohttp

logger = logging.getLogger("ModuleBase")

# Severity constants
CRITICAL = "Critical"
HIGH     = "High"
MEDIUM   = "Medium"
LOW      = "Low"

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=10)


class BaseModule:
    name: str = "BaseModule"
    description: str = "Base vulnerability detection module"

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Executes vulnerability checks against a given entrypoint.

        entrypoint keys:
            url     (str)           – full URL
            method  (str)           – HTTP method
            params  (dict|None)     – URL / query parameters
            body    (str|None)      – raw request body
            headers (dict)          – request headers
        """
        raise NotImplementedError("Each module must implement run().")

    # ------------------------------------------------------------------
    # Helpers shared by all sub-modules
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        *,
        vulnerability: str,
        vuln_id: str,
        severity: str,
        url: str,
        method: str,
        parameter: str,
        payload: str,
        evidence: str,
    ) -> Dict[str, Any]:
        return {
            "vulnerability": vulnerability,
            "vuln_id": vuln_id,
            "severity": severity,
            "url": url,
            "method": method,
            "parameter": parameter,
            "payload": payload,
            "evidence": evidence,
        }

    def _inject_param(
        self,
        entrypoint: Dict[str, Any],
        param_name: str,
        payload: str,
    ) -> Dict[str, Any]:
        """
        Returns a *mutated* copy of the entrypoint with `payload` injected
        into `param_name`. Handles query params and JSON / form bodies.
        """
        ep = copy.deepcopy(entrypoint)
        method = ep.get("method", "GET").upper()

        # --- Query / URL params ---
        if ep.get("params") and param_name in ep["params"]:
            ep["params"][param_name] = payload
            return ep

        # --- Body: JSON ---
        body = ep.get("body", "")
        if body:
            try:
                bd = json.loads(body)
                if isinstance(bd, dict) and param_name in bd:
                    bd[param_name] = payload
                    ep["body"] = json.dumps(bd)
                    if "headers" not in ep:
                        ep["headers"] = {}
                    ep["headers"]["Content-Type"] = "application/json"
                    return ep
            except (json.JSONDecodeError, TypeError):
                pass

            # --- Body: form-encoded ---
            try:
                fd = {k: v[0] for k, v in parse_qs(body).items()}
                if param_name in fd:
                    fd[param_name] = payload
                    ep["body"] = urlencode(fd)
                    if "headers" not in ep:
                        ep["headers"] = {}
                    ep["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
                    return ep
            except Exception:
                pass

        return ep

    async def _send(
        self,
        ep: Dict[str, Any],
        *,
        allow_redirects: bool = True,
    ) -> Optional[aiohttp.ClientResponse]:
        """Fire a single HTTP request and return the response, or None on error."""
        method  = ep.get("method", "GET").upper()
        url     = ep["url"]
        params  = ep.get("params") or {}
        body    = ep.get("body")
        headers = ep.get("headers", {})

        try:
            if method == "GET":
                resp = await self.session.get(
                    url, params=params, headers=headers,
                    timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects,
                )
            else:
                resp = await self.session.request(
                    method, url, params=params, data=body,
                    headers=headers, timeout=DEFAULT_TIMEOUT,
                    allow_redirects=allow_redirects,
                )
            return resp
        except Exception as exc:
            logger.debug(f"[{self.name}] request error: {exc}")
            return None
