import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import json
import aiohttp

from my_scan.modules import ALL_MODULES
from my_scan.modules.base import BaseModule

@pytest.fixture
def mock_session():
    session = AsyncMock()
    
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(return_value="root:x:0:0:root:/root:/bin/bash Error Syntax syntax error script alert(1) root SQL syntax")
    mock_resp.headers = {"Content-Type": "text/html", "Server": "nginx", "Location": "http://evil.com"}
    mock_resp.release = MagicMock()
    
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    
    session.request = MagicMock(return_value=mock_ctx)
    session.get = MagicMock(return_value=mock_ctx)
    session.post = MagicMock(return_value=mock_ctx)
    return session

@pytest.mark.asyncio
async def test_all_modules_run(mock_session):
    entrypoints = [
        {"url": "http://test.com/api?id=1", "method": "GET", "params": {"id": "1"}, "body": None, "headers": {}},
        {"url": "http://test.com/api", "method": "POST", "params": None, "body": '{"user": "admin"}', "headers": {"Content-Type": "application/json"}},
        {"url": "http://test.com/api", "method": "POST", "params": None, "body": "user=admin", "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
    ]
    
    for ModClass in ALL_MODULES:
        mod = ModClass(session=mock_session)
        for ep in entrypoints:
            findings = await mod.run(ep)
            assert isinstance(findings, list)

@pytest.mark.asyncio
async def test_all_modules_exception(mock_session):
    mock_session.request.side_effect = Exception("Network error")
    mock_session.get.side_effect = Exception("Network error")
    
    entrypoint = {"url": "http://test.com/api?id=1", "method": "GET", "params": {"id": "1"}, "body": None, "headers": {}}
    
    for ModClass in ALL_MODULES:
        mod = ModClass(session=mock_session)
        findings = await mod.run(entrypoint)
        # Should gracefully return findings (likely empty, but shouldn't crash)
        assert isinstance(findings, list)

@pytest.mark.asyncio
async def test_base_module_methods(mock_session):
    class DummyModule(BaseModule):
        name = "dummy"
        vuln_id = "dummy_vuln"
        async def run(self, entrypoint):
            return []
            
    mod = DummyModule(session=mock_session)
    
    # Test _inject_param
    ep = {"url": "http://test.com", "params": {"a": "1"}}
    mutated = mod._inject_param(ep, "a", "pay")
    assert mutated["params"]["a"] == "pay"
    
    # Test _send
    mock_resp_obj = MagicMock()
    mock_session.get = AsyncMock(return_value=mock_resp_obj)
    mock_session.request = AsyncMock(return_value=mock_resp_obj)
    
    resp = await mod._send({"method": "GET", "url": "http://test.com"})
    assert resp is not None
    
    # Test _send POST
    resp2 = await mod._send({"method": "POST", "url": "http://test.com", "body": "a=1"})
    assert resp2 is not None
    
    # Test _send Exception
    mock_session.get.side_effect = Exception("Net Error")
    resp_err = await mod._send({"method": "GET", "url": "http://test.com"})
    assert resp_err is None
