from my_scan.modules.base import BaseModule
# pyrefly: ignore [missing-import]
import aiohttp
import html
import copy

class XSSModule(BaseModule):
    name = "XSSDetector"
    description = "Detects Reflected Cross-Site Scripting (XSS) vulnerabilities"

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ]

    async def run(self, entrypoint: dict) -> list:
        findings = []
        url = entrypoint["url"]
        method = entrypoint["method"]
        params = entrypoint.get("params", {})
        headers = entrypoint.get("headers", {})

        if not params:
            return findings

        for param_name in params.keys():
            for payload in self.XSS_PAYLOADS:
                mutated_params = copy.deepcopy(params)
                mutated_params[param_name] = payload

                try:
                    if method.upper() == "GET":
                        async with self.session.get(url, params=mutated_params, headers=headers, timeout=5) as response:
                            body = await response.text()
                            if payload in body and not html.escape(payload) in body:
                                findings.append({
                                    "vulnerability": "Cross-Site Scripting (XSS)",
                                    "url": url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "method": method,
                                    "evidence": f"Unsanitized XSS payload reflection found in response body"
                                })
                                break
                    elif method.upper() == "POST":
                        async with self.session.post(url, json=mutated_params, headers=headers, timeout=5) as response:
                            body = await response.text()
                            if payload in body and not html.escape(payload) in body:
                                findings.append({
                                    "vulnerability": "Cross-Site Scripting (XSS)",
                                    "url": url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "method": method,
                                    "evidence": f"Unsanitized XSS payload reflection found in response body"
                                })
                                break
                except Exception:
                    pass

        return findings
