import pytest
from my_scan.models import ScanState, Endpoint, AppMap, AttackLogEntry, Vulnerability, ScanReport
# python3 -m pytest --cov=my_scan.session my_scan/tests/test_session.py --cov-report=term-missing
def test_scan_state():
    assert ScanState.INIT.value == "INIT"
    assert ScanState.CRAWLING.value == "CRAWLING"

def test_endpoint_to_dict():
    ep = Endpoint(url="http://test.com", method="GET")
    ep_dict = ep.to_dict()
    assert ep_dict["url"] == "http://test.com"
    assert ep_dict["method"] == "GET"
    assert ep_dict["params"] == {}
    assert ep_dict["body"] is None
    assert ep_dict["discovered_via"] == "unknown"
    assert ep_dict["content_type"] is None
    assert ep_dict["depth"] == 0
    assert ep_dict["response_status"] is None

def test_app_map_add_endpoint():
    am = AppMap()
    ep = Endpoint(url="http://test.com/api", method="POST")
    am.add_endpoint(ep)
    assert len(am.nodes) == 1
    assert "POST:http://test.com/api" in am.nodes
    
    # Adding same endpoint shouldn't duplicate
    am.add_endpoint(ep)
    assert len(am.nodes) == 1

def test_app_map_add_relation():
    am = AppMap()
    am.add_relation("http://test.com", "http://test.com/api")
    assert "http://test.com" in am.edges
    assert "http://test.com/api" in am.edges["http://test.com"]
    
    # Adding same relation shouldn't duplicate
    am.add_relation("http://test.com", "http://test.com/api")
    assert len(am.edges["http://test.com"]) == 1

def test_app_map_has_endpoint():
    am = AppMap()
    ep = Endpoint(url="http://test.com", method="GET")
    am.add_endpoint(ep)
    assert am.has_endpoint("GET", "http://test.com") is True
    assert am.has_endpoint("POST", "http://test.com") is False

def test_app_map_to_dict():
    am = AppMap()
    ep = Endpoint(url="http://test.com", method="GET")
    am.add_endpoint(ep)
    am.add_relation("http://test.com", "http://test.com/1")
    d = am.to_dict()
    assert d["total_endpoints"] == 1
    assert "GET:http://test.com" in d["nodes"]
    assert d["edges"]["http://test.com"] == ["http://test.com/1"]

def test_attack_log_entry_to_dict():
    log = AttackLogEntry(
        timestamp="2026", phase="fuzzing", vuln_type="xss", method="GET",
        url="http://test", parameter="q", location="query", payload="<script>",
        mutated_url="http://test?q=<script>", request_headers={}, request_body=None,
        response_status=200, response_latency_ms=10.555, response_body_snippet="abc",
        anomaly_detected=True, anomaly_detail="found"
    )
    d = log.to_dict()
    assert d["timestamp"] == "2026"
    assert d["response_latency_ms"] == 10.55  # Should round to 2
    assert d["anomaly_detail"] == "found"

def test_vulnerability_to_dict():
    v = Vulnerability(
        vulnerability_type="xss", severity="High", url="http://t",
        method="GET", parameter="q", payload="<script>", evidence="xyz", description="desc"
    )
    d = v.to_dict()
    assert d["vulnerability_type"] == "xss"
    assert d["severity"] == "High"
    assert d["description"] == "desc"

def test_scan_report_to_dict():
    r = ScanReport(
        target_url="http://t", state=ScanState.FINISHED.value, scan_start="t1", scan_end="t2",
        duration_seconds=1.5, endpoints_found=1, attack_vectors_sent=2
    )
    v1 = Vulnerability("xss", "High", "url", "GET", "q", "p", "e")
    v2 = Vulnerability("sqli", "Critical", "url", "GET", "q", "p", "e")
    r.vulnerabilities.extend([v1, v2])
    
    am = AppMap()
    am.add_endpoint(Endpoint("http://t", "GET"))
    r.app_map = am
    
    d = r.to_dict()
    assert d["target_url"] == "http://t"
    assert d["vulnerabilities_total"] == 2
    assert d["severity_breakdown"]["High"] == 1
    assert d["severity_breakdown"]["Critical"] == 1
    assert d["severity_breakdown"]["Low"] == 0
    assert d["app_map_summary"]["total_endpoints"] == 1

def test_scan_report_to_dict_no_app_map():
    r = ScanReport(
        target_url="http://t", state="INIT", scan_start="t1", scan_end="t2",
        duration_seconds=0, endpoints_found=0, attack_vectors_sent=0
    )
    d = r.to_dict()
    assert d["app_map_summary"] == {}
