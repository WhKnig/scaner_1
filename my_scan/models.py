from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional
import datetime


class ScanState(Enum):
    INIT = "INIT"
    CRAWLING = "CRAWLING"
    ATTACKING = "ATTACKING"
    ANALYZING = "ANALYZING"
    REPORTING = "REPORTING"
    FINISHED = "FINISHED"
    ERROR = "ERROR"


@dataclass
class Endpoint:
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    # Metadata: how was this endpoint discovered?
    discovered_via: str = "unknown"   # "html_link" | "form" | "xhr" | "fetch" | "seed"
    content_type: Optional[str] = None
    depth: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "body": self.body,
            "discovered_via": self.discovered_via,
            "content_type": self.content_type,
            "depth": self.depth,
            "response_status": self.response_status,
        }


@dataclass
class AppMap:
    nodes: Dict[str, Endpoint] = field(default_factory=dict)
    # Parent URL → set of child URLs (navigation graph)
    edges: Dict[str, Set[str]] = field(default_factory=dict)

    def add_endpoint(self, endpoint: Endpoint) -> None:
        key = f"{endpoint.method}:{endpoint.url}"
        if key not in self.nodes:
            self.nodes[key] = endpoint

    def add_relation(self, parent_url: str, child_url: str) -> None:
        if parent_url not in self.edges:
            self.edges[parent_url] = set()
        self.edges[parent_url].add(child_url)

    def has_endpoint(self, method: str, url: str) -> bool:
        return f"{method}:{url}" in self.nodes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_endpoints": len(self.nodes),
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": {k: list(v) for k, v in self.edges.items()},
        }


@dataclass
class AttackLogEntry:
    """Detailed log of a single attack vector execution."""
    timestamp: str
    phase: str                   # "fuzzing"
    vuln_type: str               # "sqli" | "xss" | "cmdi" | ...
    method: str
    url: str
    parameter: str
    location: str                # "query" | "body_json" | "body_form"
    payload: str
    mutated_url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_latency_ms: float
    response_body_snippet: str   # first 500 chars
    anomaly_detected: bool
    anomaly_detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "phase": self.phase,
            "vuln_type": self.vuln_type,
            "method": self.method,
            "url": self.url,
            "parameter": self.parameter,
            "location": self.location,
            "payload": self.payload,
            "mutated_url": self.mutated_url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_latency_ms": round(self.response_latency_ms, 2),
            "response_body_snippet": self.response_body_snippet,
            "anomaly_detected": self.anomaly_detected,
            "anomaly_detail": self.anomaly_detail,
        }


@dataclass
class Vulnerability:
    vulnerability_type: str
    severity: str                # "Critical" | "High" | "Medium" | "Low"
    url: str
    method: str
    parameter: str
    payload: str
    evidence: str
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
        }


@dataclass
class ScanReport:
    target_url: str
    state: str
    scan_start: str
    scan_end: str
    duration_seconds: float
    endpoints_found: int
    attack_vectors_sent: int
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    app_map: Optional[AppMap] = None

    def to_dict(self) -> Dict[str, Any]:
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in self.vulnerabilities:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
        return {
            "target_url": self.target_url,
            "state": self.state,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "duration_seconds": self.duration_seconds,
            "endpoints_found": self.endpoints_found,
            "attack_vectors_sent": self.attack_vectors_sent,
            "vulnerabilities_total": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "app_map_summary": self.app_map.to_dict() if self.app_map else {},
        }
