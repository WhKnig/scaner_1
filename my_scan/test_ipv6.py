from urllib.parse import urlparse

urls = [
    "http://metadata.google.internal/computeMetadata/v1/",
    "https://github.com/search/feedback",
    "http://demo.owasp-juice.shop/redirect?to=https://github.com/juice-shop/juice-shop",
    "https://github.com/search/custom_scopes"
]

for u in urls:
    try:
        urlparse(u)
        print(f"OK: {u}")
    except Exception as e:
        print(f"Error for {u}: {e}")
