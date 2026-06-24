import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from my_scan.crawler import ChromeCrawler
from my_scan.models import Endpoint

@pytest.fixture
def base_url():
    return "http://test.com"

@pytest.mark.asyncio
async def test_crawler_init(base_url):
    crawler = ChromeCrawler(base_url, max_depth=2, max_pages=10)
    assert crawler.base_url == base_url
    assert crawler.max_depth == 2
    assert crawler.max_pages == 10

@pytest.mark.asyncio
async def test_normalise(base_url):
    crawler = ChromeCrawler(base_url)
    assert crawler._normalise("http://test.com/path#fragment") == "http://test.com/path"
    assert crawler._normalise("http://test.com/path?a=1") == "http://test.com/path?a=1"
    assert crawler._normalise("invalid") == "invalid"

@pytest.mark.asyncio
async def test_is_same_origin(base_url):
    crawler = ChromeCrawler(base_url)
    assert crawler._is_same_origin("http://test.com/path") is True
    assert crawler._is_same_origin("http://other.com/path") is False

@pytest.mark.asyncio
async def test_save_app_map(base_url):
    crawler = ChromeCrawler(base_url, output_file="/dev/null")
    crawler.app_map.add_endpoint(Endpoint("http://test.com/api", "GET"))
    
    with patch("my_scan.crawler.open", mock_open()) as mocked_open:
        crawler._save_app_map()
        mocked_open.assert_called_with("/dev/null", "w", encoding="utf-8")

@pytest.mark.asyncio
async def test_start(base_url):
    crawler = ChromeCrawler(base_url, max_depth=1, max_pages=1, output_file="/dev/null")
    
    mock_playwright = AsyncMock()
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_page = AsyncMock()
    
    mock_playwright.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page
    
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_page.goto.return_value = mock_resp
    mock_page.url = "http://test.com/home"
    
    mock_page.eval_on_selector_all.side_effect = [
        ["http://test.com/about"],  # links
        [{"action": "/submit", "method": "POST", "inputs": [{"name": "q"}]}] # forms
    ]
    
    request_handler = None
    def on_side_effect(event, handler):
        nonlocal request_handler
        if event == "request":
            request_handler = handler
    
    mock_page.on = MagicMock(side_effect=on_side_effect)
    
    with patch("my_scan.crawler.async_playwright") as mock_pw_ctx:
        mock_pw_ctx.return_value.__aenter__.return_value = mock_playwright
        with patch("my_scan.crawler.open", mock_open()):
            app_map = await crawler.start()
            
    assert len(app_map.nodes) > 0

@pytest.mark.asyncio
async def test_crawl_page(base_url):
    crawler = ChromeCrawler(base_url)
    
    mock_page = AsyncMock()
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_page.goto.return_value = mock_resp
    mock_page.url = "http://test.com/home"
    
    request_handler = None
    def on_side_effect(event, handler):
        nonlocal request_handler
        if event == "request":
            request_handler = handler
            
    mock_page.on = MagicMock(side_effect=on_side_effect)
    
    mock_locator = MagicMock()
    mock_locator.element_handles = AsyncMock(return_value=[])
    mock_page.locator = MagicMock(return_value=mock_locator)

    
    mock_page.eval_on_selector_all.side_effect = [
        ["/about"],  # links
        [{"action": "/submit", "method": "POST", "inputs": [{"name": "q", "value": "1"}]}] # forms
    ]
    
    urls = await crawler._crawl_page(mock_page, AsyncMock(), "http://test.com/home", 0, None)
    
    assert "http://test.com/about" in urls
    
    nodes = list(crawler.app_map.nodes.values())
    assert any("submit" in n.url for n in nodes) or any("q" in n.params for n in nodes) or any(n.body and "q=" in n.body for n in nodes)
    mock_req = AsyncMock()
    mock_req.resource_type = "xhr"
    mock_req.url = "http://test.com/api"
    mock_req.method = "POST"
    mock_req.post_data = '{"a": "1"}'
    mock_req.all_headers.return_value = {}
    
    if request_handler:
        await request_handler(mock_req)
        await asyncio.sleep(0) # let ensure_future run
    
    # Needs a hack to let xhr requests process in crawler.py since they are async
    # In crawler.py it appends to xhr_requests, then processes at the end of _crawl_page.
    # Since we called request_handler AFTER _crawl_page finished, it won't be processed.
    # We should call request_handler INSIDE the _crawl_page mock.

@pytest.mark.asyncio
async def test_crawl_page_with_xhr(base_url):
    crawler = ChromeCrawler(base_url)
    
    mock_page = AsyncMock()
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "text/html"}
    
    request_handler = None
    def on_side_effect(event, handler):
        nonlocal request_handler
        if event == "request":
            request_handler = handler
            
    mock_page.on = MagicMock(side_effect=on_side_effect)

    mock_locator = MagicMock()
    mock_locator.element_handles = AsyncMock(return_value=[])
    mock_page.locator = MagicMock(return_value=mock_locator)

    
    async def mock_goto(*args, **kwargs):
        if request_handler:
            mock_req = AsyncMock()
            mock_req.resource_type = "xhr"
            mock_req.url = "http://test.com/api"
            mock_req.method = "POST"
            mock_req.post_data = '{"a": "1"}'
            mock_req.all_headers.return_value = {"content-type": "application/json"}
            await request_handler(mock_req)
            # Give the asyncio loop a moment to run the ensure_future
            await asyncio.sleep(0)
        return mock_resp
        
    mock_page.goto = mock_goto
    mock_page.url = "http://test.com/home"
    
    mock_page.eval_on_selector_all.side_effect = [[], []]
    
    await crawler._crawl_page(mock_page, AsyncMock(), "http://test.com/home", 0, None)
    
    nodes = list(crawler.app_map.nodes.values())
    assert any("api" in n.url for n in nodes)
