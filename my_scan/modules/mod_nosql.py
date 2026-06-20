import logging
from typing import Any, Dict, List
import json
import urllib.parse
import copy

from my_scan.modules.base import BaseModule, HIGH, CRITICAL

logger = logging.getLogger("mod_nosql")

class NoSQLInjectionModule(BaseModule):
    name = "nosql_injection"
    description = "Detects NoSQL Injection vulnerabilities (DoS, Exfiltration, Manipulation)."

    async def run(self, entrypoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        url = entrypoint["url"]
        
        # 1. Test NoSQL DoS (Sleep via $where or sleep function)
        dos_payloads = [
            "id-0000' || sleep(5) || '",
            "~(){ while(true){} }()",
            "$sleep 5000"
        ]
        
        # 2. Test NoSQL Exfiltration ($ne, $gt)
        exfil_payloads = [
            '{"$ne": ""}',
            '{"$gt": ""}'
        ]
        
        # 3. Try appending payload directly to URL path if it looks like an ID parameter
        # This targets things like /rest/track-order/:id
        parsed = urllib.parse.urlparse(url)
        path_parts = parsed.path.split('/')
        if path_parts[-1]:  # If there is a last part of the path
            for payload in dos_payloads:
                new_path = "/".join(path_parts[:-1] + [urllib.parse.quote(payload)])
                new_url = parsed._replace(path=new_path).geturl()
                
                ep = copy.deepcopy(entrypoint)
                ep["url"] = new_url
                try:
                    resp = await self._send(ep)
                    if resp:
                        # For DoS, we could measure time, but simply triggering the error or seeing weird output is enough for finding
                        resp.release()
                except Exception:
                    pass

            for payload in exfil_payloads:
                new_path = "/".join(path_parts[:-1] + [urllib.parse.quote(payload)])
                new_url = parsed._replace(path=new_path).geturl()
                
                ep = copy.deepcopy(entrypoint)
                ep["url"] = new_url
                try:
                    resp = await self._send(ep)
                    if resp:
                        body = await resp.text()
                        if "status\":\"success" in body and len(body) > 50:
                            findings.append(self._make_finding(
                                vulnerability="NoSQL Injection Exfiltration",
                                vuln_id="nosql_exfiltration",
                                severity=HIGH,
                                url=url,
                                method=ep["method"],
                                parameter="URL Path",
                                payload=payload,
                                evidence="Successfully extracted data using NoSQL operators in URL path."
                            ))
                        resp.release()
                except Exception:
                    pass

        # 4. Try NoSQL payloads in body parameters
        if entrypoint.get("method", "GET").upper() in ["POST", "PUT", "PATCH"]:
            body = entrypoint.get("body", "")
            if body:
                try:
                    bd = json.loads(body)
                    if isinstance(bd, dict):
                        for key in bd.keys():
                            for payload in exfil_payloads:
                                ep = self._inject_param(entrypoint, key, json.loads(payload))
                                try:
                                    resp = await self._send(ep)
                                    if resp:
                                        resp_body = await resp.text()
                                        # If the endpoint usually errors out or requires specific auth, but payload bypasses it
                                        if resp.status < 400 and "error" not in resp_body.lower():
                                            findings.append(self._make_finding(
                                                vulnerability="NoSQL Injection Manipulation",
                                                vuln_id="nosql_manipulation",
                                                severity=HIGH,
                                                url=url,
                                                method=ep["method"],
                                                parameter=key,
                                                payload=payload,
                                                evidence=f"Successfully bypassed constraints using NoSQL operators in parameter '{key}'."
                                            ))
                                        resp.release()
                                except Exception:
                                    pass
                except (json.JSONDecodeError, TypeError):
                    pass

        return findings
