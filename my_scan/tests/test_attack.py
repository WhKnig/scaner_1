import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from my_scan.models import AppMap, Endpoint
from my_scan.session import SessionController
from my_scan.attack import ModuleRunner, AttackGenerator, DataParser, RequestSender

@pytest.fixture
def mock_session_controller():
    sc = SessionController()
    sc.cookies = {"session": "123"}
    sc.auth_headers = {"Authorization": "Bearer tkn"}
    return sc

@pytest.fixture
def app_map():
    am = AppMap()
    ep = Endpoint(url="http://test.com/api?id=1", method="GET", params={"id": "1"}, body='{"key": "val"}')
    am.add_endpoint(ep)
    return am

@pytest.mark.asyncio
async def test_module_runner_run_all(mock_session_controller, app_map):
    runner = ModuleRunner(mock_session_controller, log_file="/dev/null")
    
    # Mock ALL_MODULES
    mock_module_instance = AsyncMock()
    mock_module_instance.run.return_value = [{
        "vuln_id": "sqli", 
        "severity": "High",
        "method": "GET",
        "url": "http://test.com/api",
        "parameter": "id",
        "payload": "1'"
    }]
    mock_module_class = MagicMock(return_value=mock_module_instance)
    mock_module_class.name = "TestModule"
    
    with patch("my_scan.attack.ALL_MODULES", [mock_module_class]):
        raw, vulns = await runner.run_all(app_map)
        
    assert len(vulns) == 1
    assert vulns[0].vulnerability_type == "sqli"

@pytest.mark.asyncio
async def test_module_runner_exception(mock_session_controller, app_map):
    runner = ModuleRunner(mock_session_controller, log_file="/dev/null")
    
    mock_module_instance = AsyncMock()
    mock_module_instance.run.side_effect = Exception("Module crashed")
    mock_module_class = MagicMock(return_value=mock_module_instance)
    mock_module_class.name = "CrashModule"
    
    with patch("my_scan.attack.ALL_MODULES", [mock_module_class]):
        raw, vulns = await runner.run_all(app_map)
        
    assert len(vulns) == 0

def test_endpoint_to_entrypoint():
    ep = Endpoint(url="http://test.com/api?a=1", method="POST", params={"b": "2"}, headers={"X": "Y"}, body="123")
    entry = ModuleRunner._endpoint_to_entrypoint(ep)
    
    assert entry["url"] == "http://test.com/api?a=1"
    assert entry["method"] == "POST"
    assert entry["params"] == {"a": "1", "b": "2"}
    assert entry["headers"] == {"X": "Y"}
    assert entry["body"] == "123"

def test_attack_generator(app_map):
    gen = AttackGenerator(["sqli"])
    vectors = gen.generate_vectors(app_map)
    assert len(vectors) > 0
    assert vectors[0]["type"] == "sqli"

def test_attack_generator_fallback():
    gen = AttackGenerator(["xss"])
    am = AppMap()
    am.add_endpoint(Endpoint(url="http://test.com/", method="GET"))
    vectors = gen.generate_vectors(am)
    assert len(vectors) > 0
    assert vectors[0]["parameter"] in ["id", "username", "password", "q", "search", "email", "userid", "query", "url", "redirect", "file", "path", "cmd", "exec", "input"]

def test_data_parser_query():
    ep = Endpoint(url="http://test.com/api?q=1", method="GET")
    url, hdrs, body = DataParser.inject_vector(ep, "q", "query", "pay")
    assert "q=pay" in url

def test_data_parser_body_json():
    ep = Endpoint(url="http://test.com/api", method="POST", body='{"q":"1"}')
    url, hdrs, body = DataParser.inject_vector(ep, "q", "body_json", "pay")
    assert '"q": "pay"' in body
    assert hdrs["Content-Type"] == "application/json"

def test_data_parser_body_form():
    ep = Endpoint(url="http://test.com/api", method="POST", body='q=1&z=2')
    url, hdrs, body = DataParser.inject_vector(ep, "q", "body_form", "pay")
    assert 'q=pay' in body
    assert hdrs["Content-Type"] == "application/x-www-form-urlencoded"

def test_data_parser_json_fallback():
    ep = Endpoint(url="http://test.com/api", method="POST", body='{"a":"b"}')
    url, hdrs, body = DataParser.inject_vector(ep, "q", "json", "pay")
    assert '"q": "pay"' in body
    assert hdrs["Content-Type"] == "application/json"

def test_parse_body():
    assert AttackGenerator._parse_body('{"a": 1}') == ["a"]
    assert AttackGenerator._parse_body('a=1&b=2') == ["a", "b"]
    assert AttackGenerator._parse_body('invalid') == []

def test_body_format():
    assert AttackGenerator._body_format('{"a": 1}') == "body_json"
    assert AttackGenerator._body_format('a=1&b=2') == "body_form"

@pytest.mark.asyncio
async def test_request_sender(mock_session_controller):
    sender = RequestSender(mock_session_controller, log_file="/dev/null")
    
    vec = {
        "endpoint": Endpoint("http://test.com", "GET"),
        "parameter": "q",
        "location": "query",
        "payload": "x",
        "type": "xss"
    }
    
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.text.return_value = "hello"
    
    # We must mock the context manager returned by session.get
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_resp
    
    with patch("aiohttp.ClientSession.get", return_value=mock_ctx):
        with patch("my_scan.attack.open", mock_open()):
            results = await sender.execute_queue([vec])
    
    assert len(results) == 1
    assert results[0]["status"] == 200
    assert results[0]["body"] == "hello"

@pytest.mark.asyncio
async def test_request_sender_post(mock_session_controller):
    sender = RequestSender(mock_session_controller, log_file="/dev/null")
    
    vec = {
        "endpoint": Endpoint("http://test.com", "POST"),
        "parameter": "q",
        "location": "body_json",
        "payload": "x",
        "type": "xss"
    }
    
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {}
    mock_resp.text.return_value = "hello"
    
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_resp
    
    with patch("aiohttp.ClientSession.request", return_value=mock_ctx):
        with patch("my_scan.attack.open", mock_open()):
            results = await sender.execute_queue([vec])
    
    assert len(results) == 1
    assert results[0]["status"] == 200

@pytest.mark.asyncio
async def test_request_sender_timeout(mock_session_controller):
    sender = RequestSender(mock_session_controller, log_file="/dev/null")
    
    vec = {
        "endpoint": Endpoint("http://test.com", "GET"),
        "parameter": "q",
        "location": "query",
        "payload": "x",
        "type": "xss"
    }
    
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.side_effect = asyncio.TimeoutError()
    
    with patch("aiohttp.ClientSession.get", return_value=mock_ctx):
        with patch("my_scan.attack.open", mock_open()):
            results = await sender.execute_queue([vec])
    
    assert len(results) == 0

@pytest.mark.asyncio
async def test_request_sender_exception(mock_session_controller):
    sender = RequestSender(mock_session_controller, log_file="/dev/null")
    
    vec = {
        "endpoint": Endpoint("http://test.com", "GET"),
        "parameter": "q",
        "location": "query",
        "payload": "x",
        "type": "xss"
    }
    
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.side_effect = Exception("Network error")
    
    with patch("aiohttp.ClientSession.get", return_value=mock_ctx):
        with patch("my_scan.attack.open", mock_open()):
            results = await sender.execute_queue([vec])
    
    assert len(results) == 0
