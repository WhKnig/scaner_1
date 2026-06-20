import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from my_scan.scanner import ScanManager
from my_scan.models import Endpoint, ScanState, AppMap

@pytest.fixture
def mock_session_controller():
    with patch("my_scan.scanner.SessionController") as MockSessionController:
        mock_sc = MockSessionController.return_value
        mock_sc.cookies = {}
        mock_sc.auth_headers = {}
        mock_sc.perform_login = AsyncMock(return_value=True)
        yield mock_sc

@pytest.fixture
def manager(mock_session_controller):
    return ScanManager(auth_url="http://test.com/login", auth_creds={"user":"a","pass":"b"}, output_dir="/tmp/scan_output")

@pytest.mark.asyncio
async def test_scanner_init():
    m = ScanManager()
    assert m.state == ScanState.INIT

@pytest.mark.asyncio
async def test_start_scan_success(manager):
    with patch("my_scan.scanner.open", mock_open()):
        with patch.object(manager, "_run_lifecycle", new_callable=AsyncMock) as mock_lifecycle:
            with patch("playwright.async_api.async_playwright") as mock_pw:
                mock_browser = AsyncMock()
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__.return_value = mock_browser
                mock_pw.return_value = mock_ctx
                
                with patch.object(manager, "_build_report", return_value=MagicMock()):
                    with patch.object(manager, "_save_json_report"):
                        with patch.object(manager, "_generate_html_report"):
                            with patch.object(manager, "_print_summary"):
                                await manager.start_scan("http://test.com")
                                
    assert manager.state == ScanState.FINISHED
    mock_lifecycle.assert_called_once()

@pytest.mark.asyncio
async def test_start_scan_exception(manager):
    with patch("my_scan.scanner.open", mock_open()):
        with patch.object(manager, "_run_lifecycle", side_effect=Exception("Test Exception")):
            with patch("playwright.async_api.async_playwright") as mock_pw:
                mock_browser = AsyncMock()
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__.return_value = mock_browser
                mock_pw.return_value = mock_ctx
                
                with patch.object(manager, "_build_report", return_value=MagicMock()):
                    with patch.object(manager, "_save_json_report"):
                        with patch.object(manager, "_generate_html_report"):
                            with patch.object(manager, "_print_summary"):
                                await manager.start_scan("http://test.com")
                                
    assert manager.state == ScanState.ERROR

@pytest.mark.asyncio
async def test_crawl_seeds(manager):
    mock_app_map = AppMap()
    mock_app_map.add_endpoint(Endpoint("http://test.com/new", "GET"))
    
    with patch("my_scan.scanner.ChromeCrawler") as MockCrawler:
        mock_crawler = MockCrawler.return_value
        mock_crawler.start = AsyncMock(return_value=mock_app_map)
        
        with patch("my_scan.scanner.open", mock_open()):
            new_endpoints = await manager._crawl_seeds(["http://test.com"])
            
    assert len(new_endpoints) == 1
    assert new_endpoints[0].url == "http://test.com/new"

@pytest.mark.asyncio
async def test_attack_endpoints(manager):
    endpoints = [Endpoint("http://test.com/api", "GET")]
    
    with patch("my_scan.scanner.ModuleRunner") as MockRunner:
        mock_runner = MockRunner.return_value
        mock_runner.run_all = AsyncMock(return_value=([{"result": "success"}], []))
        
        with patch("my_scan.scanner.AttackGenerator") as MockGenerator:
            mock_gen = MockGenerator.return_value
            mock_gen.generate_vectors.return_value = [{"vector": "1"}]
            
            with patch("my_scan.scanner.RequestSender") as MockSender:
                mock_sender = MockSender.return_value
                mock_sender.execute_queue = AsyncMock(return_value=[{"result": "success"}])
                
                raw_results = await manager._attack_endpoints(endpoints)
                
    assert len(raw_results) == 1
    assert raw_results[0]["result"] == "success"

@pytest.mark.asyncio
async def test_analyze_results(manager):
    results = [{"status": 200}]
    with patch("my_scan.scanner.ResponseAnalyzer") as MockAnalyzer:
        mock_analyzer = MockAnalyzer.return_value
        mock_analyzer.analyze_all.return_value = [{"vuln_id": "sqli", "severity": "High"}]
        
        with patch("my_scan.scanner.Classifier") as MockClassifier:
            mock_classifier = MockClassifier.return_value
            mock_classifier.filter_false_positives.return_value = [{"vuln_id": "sqli", "severity": "High"}]
            
            vulns = manager._analyze_results(results)
            
    assert len(vulns) == 1

def test_extract_new_urls_from_results(manager):
    manager.target_url = "http://test.com"
    raw_results = [{"mutated_url": "http://test.com/vuln", "body": "href='http://test.com/new_page'"}]
    urls = manager._extract_new_urls_from_results(raw_results)
    assert "http://test.com/new_page" in urls

@pytest.mark.asyncio
async def test_run_lifecycle(manager):
    manager.target_url = "http://test.com"
    manager.max_cycles = 1
    
    with patch.object(manager, "_crawl_seeds", new_callable=AsyncMock) as mock_crawl:
        mock_crawl.return_value = [Endpoint("http://test.com/new", "GET")]
        
        with patch.object(manager, "_attack_endpoints", new_callable=AsyncMock) as mock_attack:
            mock_attack.return_value = []
            
            with patch.object(manager, "_analyze_results") as mock_analyze:
                mock_analyze.return_value = []
                
                with patch.object(manager, "_extract_new_urls_from_results") as mock_extract:
                    mock_extract.return_value = []
                    
                    await manager._run_lifecycle()
                    
    assert mock_crawl.call_count == 1
    assert mock_attack.call_count == 1
