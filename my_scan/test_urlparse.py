import re
from urllib.parse import urlparse

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>)\\]+", re.IGNORECASE
)

body = """
http://example.com/foo
https://[2001:db8::1]/
https://[invalid::v6]/
https://demo.owasp-juice.shop/api/Quantitys/
"""

for m in URL_PATTERN.finditer(body):
    url = m.group(0).rstrip(".,;)'\"")
    print(f"Testing URL: {url}")
    try:
        parsed = urlparse(url)
        print(f"  -> Parsed netloc: {parsed.netloc}")
    except Exception as e:
        print(f"  -> Error: {e}")

