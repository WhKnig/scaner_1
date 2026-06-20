import pytest
from my_scan.analyzer import ResponseAnalyzer, Classifier
from my_scan.models import Endpoint, Vulnerability

@pytest.fixture
def analyzer():
    return ResponseAnalyzer()

@pytest.fixture
def base_result():
    ep = Endpoint(url="http://test.com/api", method="GET")
    return {
        "status": 200,
        "latency": 0.1,
        "body": "ok",
        "vector": {
            "type": "sqli",
            "payload": "' OR 1=1--",
            "parameter": "id",
            "endpoint": ep
        }
    }

def test_detect_anomalies_empty(analyzer):
    assert analyzer.detect_anomalies({}) == []

def test_detect_anomalies_sqli(analyzer, base_result):
    base_result["body"] = "error: you have an error in your sql syntax near ''"
    anomalies = analyzer.detect_anomalies(base_result)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "sqli"
    assert anomalies[0]["severity"] == "High"

def test_detect_anomalies_nosqli(analyzer, base_result):
    base_result["body"] = "mongoexception: connection failed"
    anomalies = analyzer.detect_anomalies(base_result)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "nosqli"

def test_detect_anomalies_cmdi(analyzer, base_result):
    base_result["body"] = "uid=1000(user) gid=1000(user)"
    anomalies = analyzer.detect_anomalies(base_result)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "cmdi"
    assert anomalies[0]["severity"] == "Critical"

def test_detect_anomalies_xss(analyzer, base_result):
    base_result["vector"]["type"] = "xss"
    base_result["vector"]["payload"] = "<script>alert(1)</script>"
    base_result["body"] = "hello <script>alert(1)</script>"
    
    anomalies = analyzer.detect_anomalies(base_result)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "xss"

def test_detect_anomalies_xss_miss(analyzer, base_result):
    base_result["vector"]["type"] = "xss"
    base_result["vector"]["payload"] = "<script>alert(1)</script>"
    base_result["body"] = "hello"  # payload not reflected
    
    anomalies = analyzer.detect_anomalies(base_result)
    assert len(anomalies) == 0

def test_detect_anomalies_time_delay(analyzer, base_result):
    base_result["vector"]["payload"] = "sleep(5)"
    base_result["latency"] = 5.1
    anomalies = analyzer.detect_anomalies(base_result)
    assert len(anomalies) == 1
    assert anomalies[0]["evidence"].startswith("Time delay anomaly detected")

def test_detect_anomalies_status_500(analyzer, base_result):
    base_result["status"] = 500
    anomalies = analyzer.detect_anomalies(base_result)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "potential_sqli"
    assert anomalies[0]["severity"] == "Medium"

def test_filter_false_positives_xss():
    classifier = Classifier()
    anomalies = [{"type": "xss", "severity": "High", "evidence": "found"}]
    result = {
        "body": "escaped: &lt;script&gt; and also the payload <script>alert(1)</script>",
        "vector": {"payload": "<script>alert(1)</script>"}
    }
    filtered = classifier.filter_false_positives(anomalies, result)
    assert len(filtered) == 0

def test_filter_false_positives_latency():
    classifier = Classifier()
    anomalies = [{"type": "sqli", "severity": "High", "evidence": "latency is high"}]
    result = {"latency": 16.0}
    filtered = classifier.filter_false_positives(anomalies, result)
    assert len(filtered) == 0

def test_filter_false_positives_valid():
    classifier = Classifier()
    anomalies = [{"type": "sqli", "severity": "High", "evidence": "sql syntax error"}]
    result = {"body": "error"}
    filtered = classifier.filter_false_positives(anomalies, result)
    assert len(filtered) == 1

def test_classify(base_result):
    classifier = Classifier()
    anomaly = {"type": "sqli", "severity": "High", "evidence": "sql error"}
    vuln = classifier.classify(anomaly, base_result)
    
    assert isinstance(vuln, Vulnerability)
    assert vuln.vulnerability_type == "sqli"
    assert vuln.severity == "High"
    assert vuln.url == "http://test.com/api"
    assert vuln.method == "GET"
    assert vuln.parameter == "id"
    assert vuln.payload == "' OR 1=1--"
    assert vuln.evidence == "sql error"
    assert "appears vulnerable to SQLI" in vuln.description
