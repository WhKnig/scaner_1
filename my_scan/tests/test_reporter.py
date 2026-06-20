import pytest
import os
import tempfile
from my_scan.reporter import HTMLReporter
from my_scan.models import ScanReport, Vulnerability, Endpoint

def test_html_reporter():
    report = ScanReport(
        target_url="http://test.com",
        state="FINISHED",
        scan_start="2024-01-01",
        scan_end="2024-01-01",
        duration_seconds=10.0,
        endpoints_found=1,
        attack_vectors_sent=1,
        vulnerabilities=[Vulnerability("sqli", "High", "http://test.com", "GET", "q", "pay", "evidence")]
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        reporter = HTMLReporter()
        
        # Create a dummy attack log file
        log_path = os.path.join(tmpdir, "attack_log.jsonl")
        with open(log_path, "w") as f:
            f.write("{}")
            
        out_path = os.path.join(tmpdir, "report.html")
        reporter.generate(report, log_path, out_path)
        
        report_file = out_path
        assert os.path.exists(report_file)
        
        with open(report_file, "r") as f:
            content = f.read()
            assert "Scan Report" in content
            assert "sqli" in content
            assert "High" in content
            assert "http://test.com" in content
