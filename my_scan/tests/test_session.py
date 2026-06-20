import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from my_scan.session import SessionController

@pytest.fixture
def mock_page():
    page = AsyncMock()
    page.url = "http://test.com/login"
    
    # Mock locator
    locator_mock = AsyncMock()
    locator_mock.is_visible.return_value = True
    page.locator = MagicMock(return_value=locator_mock)
    
    # Mock context cookies
    page.context.cookies.return_value = [{"name": "session", "value": "123"}]
    
    return page

@pytest.mark.asyncio
async def test_session_init():
    sc = SessionController()
    assert sc.auth_url is None
    assert sc.is_authenticated is False
    
@pytest.mark.asyncio
async def test_perform_login_no_auth():
    sc = SessionController()
    page = AsyncMock()
    result = await sc.perform_login(page)
    assert result is True

@pytest.mark.asyncio
async def test_perform_login_success(mock_page):
    sc = SessionController("http://test.com/login", {"username": "u", "password": "p"})
    
    # Test request interception
    request_mock = AsyncMock()
    request_mock.all_headers.return_value = {"authorization": "Bearer token"}
    
    request_handler = None
    def on_side_effect(event, handler):
        nonlocal request_handler
        if event == "request":
            request_handler = handler
    
    mock_page.on = MagicMock(side_effect=on_side_effect)
    
    async def mock_wait_for_load_state(*args, **kwargs):
        if request_handler:
            task = request_handler(request_mock)
            if isinstance(task, asyncio.Task):
                await task

    mock_page.wait_for_load_state.side_effect = mock_wait_for_load_state

    result = await sc.perform_login(mock_page)
    
    assert result is True
    assert sc.is_authenticated is True
    assert sc.cookies == {"session": "123"}
    assert sc.auth_headers.get("Authorization") == "Bearer token"
    assert sc.check_alive_url == "http://test.com/login"

@pytest.mark.asyncio
async def test_perform_login_inputs_not_found(mock_page):
    sc = SessionController("http://test.com/login", {"username": "u", "password": "p"})
    
    # Make locator invisible
    locator_mock = AsyncMock()
    locator_mock.is_visible.return_value = False
    mock_page.locator.return_value = locator_mock
    
    result = await sc.perform_login(mock_page)
    assert result is False
    assert sc.is_authenticated is False

@pytest.mark.asyncio
async def test_perform_login_exception(mock_page):
    sc = SessionController("http://test.com/login", {"username": "u", "password": "p"})
    mock_page.goto.side_effect = Exception("Network Error")
    
    result = await sc.perform_login(mock_page)
    assert result is False

@pytest.mark.asyncio
async def test_check_alive_no_auth():
    sc = SessionController()
    page = AsyncMock()
    result = await sc.check_alive(page)
    assert result is True

@pytest.mark.asyncio
async def test_check_alive_no_check_url():
    sc = SessionController("http://test.com/login", {"username": "u", "password": "p"})
    page = AsyncMock()
    result = await sc.check_alive(page)
    assert result is True

@pytest.mark.asyncio
async def test_check_alive_success(mock_page):
    sc = SessionController("http://auth", {"u": "p"}, "http://check")
    sc.is_authenticated = True
    
    response_mock = AsyncMock()
    response_mock.status = 200
    mock_page.goto.return_value = response_mock
    mock_page.url = "http://check"
    mock_page.content.return_value = "<html>Dashboard</html>"
    
    result = await sc.check_alive(mock_page)
    assert result is True
    assert sc.is_authenticated is True

@pytest.mark.asyncio
async def test_check_alive_no_response(mock_page):
    sc = SessionController("http://auth", {"u": "p"}, "http://check")
    mock_page.goto.return_value = None
    result = await sc.check_alive(mock_page)
    assert result is False

@pytest.mark.asyncio
async def test_check_alive_redirected(mock_page):
    sc = SessionController("http://auth", {"u": "p"}, "http://check")
    response_mock = AsyncMock()
    response_mock.status = 200
    mock_page.goto.return_value = response_mock
    mock_page.url = "http://auth/redirect"
    
    result = await sc.check_alive(mock_page)
    assert result is False

@pytest.mark.asyncio
async def test_check_alive_401(mock_page):
    sc = SessionController("http://auth", {"u": "p"}, "http://check")
    response_mock = AsyncMock()
    response_mock.status = 401
    mock_page.goto.return_value = response_mock
    mock_page.url = "http://check"
    
    result = await sc.check_alive(mock_page)
    assert result is False

@pytest.mark.asyncio
async def test_check_alive_login_form_detected(mock_page):
    sc = SessionController("http://auth", {"u": "p"}, "http://check")
    response_mock = AsyncMock()
    response_mock.status = 200
    mock_page.goto.return_value = response_mock
    mock_page.url = "http://check"
    mock_page.content.return_value = "<html>Please sign in here</html>"
    
    locator_mock = AsyncMock()
    locator_mock.is_visible.return_value = True
    mock_page.locator.return_value = locator_mock
    
    result = await sc.check_alive(mock_page)
    assert result is False

@pytest.mark.asyncio
async def test_check_alive_exception(mock_page):
    sc = SessionController("http://auth", {"u": "p"}, "http://check")
    mock_page.goto.side_effect = Exception("Boom")
    result = await sc.check_alive(mock_page)
    assert result is False

@pytest.mark.asyncio
async def test_perform_login_submit_fallback(mock_page):
    # Test when submit is not found, it falls back to pressing Enter
    sc = SessionController("http://test.com/login", {"username": "u", "password": "p"})
    
    # Mock locator: visible for inputs, hidden for submit
    def locator_side_effect(selector):
        lm = AsyncMock()
        if "submit" in selector or "Log" in selector or "Sign" in selector:
            lm.is_visible.return_value = False
        else:
            lm.is_visible.return_value = True
        return lm
        
    mock_page.locator = MagicMock(side_effect=locator_side_effect)
    
    result = await sc.perform_login(mock_page)
    assert result is True
    mock_page.keyboard.press.assert_called_with("Enter")
