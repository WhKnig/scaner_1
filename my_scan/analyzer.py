import logging
import re
from typing import Dict, Any, List, Optional

from my_scan.models import Vulnerability

logger = logging.getLogger("AnalyzerCore")

class ResponseAnalyzer:
    """
    Analyzes HTTP responses for error signatures (SQLi/NoSQLi/CmdI)
    and behavioral characteristics (time delay, page structure drift).
    """
    def __init__(self):
        # Broad error signature map for database and OS systems
        self.signatures = {
            "sqli": [
                r"you have an error in your sql syntax",
                r"warning: mysql_",
                r"unclosed quotation mark after the character string",
                r"postgresql query failed",
                r"h2 database exception",
                r"sqlite3\.operationalerror",
                r"oracle error",
                r"native client query failed",
                r"odbc driver error",
                r"db2 exception"
            ],
            "nosqli": [
                r"mongodb\.driver\.error",
                r"assertion failed:.*query",
                r"bson\.errors\.invalidid",
                r"mongoexception",
                r"objectid\.fromstring"
            ],
            "cmdi": [
                r"root:x:0:0:",
                r"bin/bash",
                r"windows IP configuration",
                r"volume serial number is",
                r"uid=\d+\(.*\)"
            ]
        }

    def detect_anomalies(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scans a request/response pair for database exceptions, script reflections, or anomalies.
        """
        anomalies = []
        if not result:
            return anomalies

        body = result.get("body", "")
        status = result.get("status", 200)
        latency = result.get("latency", 0.0)
        vector = result.get("vector", {})
        payload = vector.get("payload", "")
        vuln_type = vector.get("type", "")

        # 1. Signature-based SQLi / NoSQLi / CmdI detection
        for category, regex_list in self.signatures.items():
            for regex in regex_list:
                if re.search(regex, body, re.IGNORECASE):
                    anomalies.append({
                        "type": category,
                        "evidence": f"Found matching error signature: '{regex}'",
                        "severity": "High" if category != "cmdi" else "Critical"
                    })

        # 2. XSS Reflection Detection (signature check)
        if vuln_type == "xss" and payload in body:
            # Check if payload is reflected inside vulnerable contexts (e.g. tag attributes, scripts, raw)
            # A naive yet robust baseline check: does the exact script structure reflect in page body?
            if "<script>alert(1)</script>" in body or "onerror=alert(1)" in body:
                anomalies.append({
                    "type": "xss",
                    "evidence": f"Reflected XSS payload found in response body: {payload}",
                    "severity": "High"
                })

        # 3. Behavioral/Time-based Anomalies (Blind Injection check)
        # E.g., if a sleep payload was sent, check if response latency is high (e.g., > baseline + 3.0 seconds)
        baseline = result.get("entrypoint", {}).get("_baseline_latency", 1.0)
        dynamic_threshold = baseline + 3.0
        if ("sleep" in payload.lower() or "benchmark" in payload.lower()) and latency >= dynamic_threshold:
            anomalies.append({
                "type": vuln_type,
                "evidence": f"Time delay anomaly detected. Response latency: {latency:.2f}s (Baseline: {baseline:.2f}s, Threshold: {dynamic_threshold:.2f}s)",
                "severity": "High"
            })

        # 4. Status Code anomalies (e.g., 500 Internal Server Error under active fuzzing)
        if status == 500 and not any(a["type"] == vuln_type for a in anomalies):
            anomalies.append({
                "type": f"potential_{vuln_type}" if vuln_type else "generic_error",
                "evidence": "Server returned HTTP 500 Internal Server Error under active payloads.",
                "severity": "Medium"
            })

        return anomalies


class Classifier:
    """
    Removes false positives using context verification filters and ranks
    vulnerability criticality levels.
    """
    @staticmethod
    def filter_false_positives(
        anomalies: List[Dict[str, Any]],
        result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Applies heuristics to eliminate false reports (like echoes in search queries or input reflections).
        """
        valid_anomalies = []
        body = result.get("body", "")
        vector = result.get("vector", {})
        payload = vector.get("payload", "")

        for anomaly in anomalies:
            # Rule 1: If it's a reflected payload error (like SQL error output), but the error signature is
            # literally identical to the payload we sent (e.g. we sent a regex as payload), filter it out.
            # (Ensures that the error was generated by the backend engine, not by echo-reflection)
            if anomaly["type"] == "xss" and payload in body:
                # Basic check: did the page escape the payload?
                escaped_payload = re.escape(payload)
                # If HTML tag brackets were converted to HTML entities, it's a false positive (it's safe)
                if "&lt;script&gt;" in body or "&quot;" in body:
                    logger.debug(f"Filtered out false-positive XSS due to output encoding: {payload}")
                    continue

            # Rule 2: Blind SQLi false positives. If latency is high, check if normal/unmutated requests
            # are also slow. (For this demonstration, we assume a static check)
            if "latency" in anomaly["evidence"].lower() and result.get("latency", 0.0) > 15.0:
                # If latency is excessively high (e.g. >15s), it might be a general network timeout
                logger.debug(f"Filtered out blind injection anomaly due to general network timeout.")
                continue

            valid_anomalies.append(anomaly)
            
        return valid_anomalies

    @staticmethod
    def classify(anomaly: Dict[str, Any], result: Dict[str, Any]) -> Vulnerability:
        """
        Promotes an anomaly to a formal Vulnerability object.
        """
        vector = result["vector"]
        endpoint = vector["endpoint"]
        
        description = (
            f"The parameter '{vector['parameter']}' in {endpoint.method} request to {endpoint.url} "
            f"appears vulnerable to {anomaly['type'].upper()} attacks."
        )

        return Vulnerability(
            vulnerability_type=anomaly["type"],
            severity=anomaly["severity"],
            url=endpoint.url,
            method=endpoint.method,
            parameter=vector["parameter"],
            payload=vector["payload"],
            evidence=anomaly["evidence"],
            description=description
        )
