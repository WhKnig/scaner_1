import logging
import asyncio
from typing import Dict, Any, Optional
from playwright.async_api import BrowserContext, Page

logger = logging.getLogger("SessionController")

class SessionController:
    """
    Manages session lifecycle, authentication, token extraction (Cookies/JWT),
    and session liveness validation for SPA and traditional web applications.
    """
    def __init__(
        self,
        auth_url: Optional[str] = None,
        auth_creds: Optional[Dict[str, str]] = None,
        check_alive_url: Optional[str] = None
    ):
        self.auth_url = auth_url
        self.auth_creds = auth_creds
        self.check_alive_url = check_alive_url
        
        self.cookies: Dict[str, str] = {}
        self.auth_headers: Dict[str, str] = {}
        self.is_authenticated = False

    async def perform_login(self, page: Page) -> bool:
        """
        Navigates to the login page, identifies input fields dynamically,
        fills credentials, submits the form, and extracts cookies and JWT headers.
        """
        if not self.auth_url or not self.auth_creds:
            logger.info("No authentication credentials provided. Proceeding with anonymous session.")
            return True

        logger.info(f"Initiating login sequence at: {self.auth_url}")
        try:
            # Go to the login page and wait for loading to settle
            await page.goto(self.auth_url, wait_until="networkidle", timeout=15000)
            
            # Extract credentials
            username = self.auth_creds.get("username", "")
            password = self.auth_creds.get("password", "")

            # Typical input field selectors
            user_selectors = ["input[name='username']", "input[type='text']", "input[placeholder*='user']", "input[placeholder*='email']", "input[id*='user']"]
            pass_selectors = ["input[name='password']", "input[type='password']", "input[placeholder*='pass']", "input[id*='pass']"]
            submit_selectors = ["button[type='submit']", "button:has-text('Log')", "button:has-text('Sign')", "input[type='submit']"]

            # Locate username field
            user_found = False
            for sel in user_selectors:
                try:
                    locator = page.locator(sel)
                    if await locator.is_visible(timeout=1000):
                        await locator.fill(username)
                        user_found = True
                        logger.debug(f"Filled username using selector: {sel}")
                        break
                except Exception:
                    continue

            # Locate password field
            pass_found = False
            for sel in pass_selectors:
                try:
                    locator = page.locator(sel)
                    if await locator.is_visible(timeout=1000):
                        await locator.fill(password)
                        pass_found = True
                        logger.debug(f"Filled password using selector: {sel}")
                        break
                except Exception:
                    continue

            if not user_found or not pass_found:
                logger.error("Failed to identify username/password inputs on the page.")
                return False

            # Intercept request headers to detect if SPA issues a JWT / Bearer token via Fetch
            jwt_token = None
            
            # Intercept request headers to detect if SPA issues a JWT / Bearer token via Fetch
            jwt_token = None
            
            async def intercept_request(req):
                nonlocal jwt_token
                try:
                    headers = await req.all_headers()
                    auth_val = headers.get("authorization")
                    if auth_val and "bearer" in auth_val.lower():
                        jwt_token = auth_val
                        logger.info("Captured Authorization Header during navigation.")
                except Exception:
                    # Ignore TargetClosedError or other network errors during intercept
                    pass

            page.on("request", lambda req: asyncio.create_task(intercept_request(req)))

            # Click submit
            submit_clicked = False
            for sel in submit_selectors:
                try:
                    locator = page.locator(sel)
                    if await locator.is_visible(timeout=1000):
                        await locator.click()
                        submit_clicked = True
                        logger.debug(f"Clicked submit button using selector: {sel}")
                        break
                except Exception:
                    continue

            if not submit_clicked:
                logger.warning("Submit button not found. Sending 'Enter' key.")
                await page.keyboard.press("Enter")

          
            await page.wait_for_load_state("networkidle", timeout=10000)
            
            cookies = await page.context.cookies()
            self.cookies = {c["name"]: c["value"] for c in cookies}
            logger.info(f"Login completed. Extracted {len(self.cookies)} cookies.")

            if jwt_token:
                self.auth_headers["Authorization"] = jwt_token
            
            
            if not self.check_alive_url:
                self.check_alive_url = page.url
                logger.debug(f"Inferred check_alive_url: {self.check_alive_url}")

            self.is_authenticated = True
            return True
        except Exception as e:
            logger.exception(f"Unexpected error during login sequence: {e}")
            return False

    async def check_alive(self, page: Page) -> bool:
        """
        Verifies if the scanner's session is still active by navigating to the
        session check URL or analyzing response characteristics.
        """
        if not self.auth_url or not self.auth_creds:
            # Anonymous session is always considered "alive"
            return True

        if not self.check_alive_url:
            logger.warning("No check_alive URL configured. Assuming session is alive.")
            return True

        logger.info(f"Checking session health at: {self.check_alive_url}")
        try:
            # Perform a page navigation to the session check URL
            response = await page.goto(self.check_alive_url, wait_until="networkidle", timeout=10000)
            if not response:
                logger.warning("No response received during check_alive.")
                return False

            # Check if we were redirected back to the login or auth page
            current_url = page.url
            if self.auth_url in current_url and current_url != self.auth_url:
                logger.warning(f"Session invalidated. Redirected to login page: {current_url}")
                self.is_authenticated = False
                return False

            # Check HTTP status code (e.g. 401 or 403 indicates invalid session)
            status = response.status
            if status in [401, 403]:
                logger.warning(f"Session check returned HTTP {status}. Session expired.")
                self.is_authenticated = False
                return False

            # Inspect page content for indicators of a guest/non-logged-in session
            content = await page.content()
            logout_keywords = ["sign in", "login", "authorized", "enter credentials"]
            # But only if these terms dominate or login inputs appear
            if any(kw in content.lower() for kw in logout_keywords) and await page.locator("input[type='password']").is_visible(timeout=500):
                logger.warning("Login fields detected on check_alive page. Session expired.")
                self.is_authenticated = False
                return False

            logger.info("Session is active and healthy.")
            return True
        except Exception as e:
            logger.error(f"Error checking session status: {e}")
            return False
