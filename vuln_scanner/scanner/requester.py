# scanner/requester.py
import requests
from requests.adapters import HTTPAdapter, Retry

DEFAULT_HEADERS = {
    "User-Agent": "VulnScanner/0.1 (+https://example.com)"
}

def create_session(retries: int = 2, backoff: float = 0.5, timeout: int = 10, pool_size: int = 20):
    s = requests.Session()
    s.headers.update(DEFAULT_HEADERS)
    retry = Retry(total=retries, backoff_factor=backoff, status_forcelist=[429,500,502,503,504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_size, pool_maxsize=pool_size)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s._timeout = timeout
    return s

def send_get(session, url: str, timeout: int = None):
    """Send GET request with session. Returns requests.Response or None on error."""
    try:
        t = timeout or getattr(session, "_timeout", 10)
        r = session.get(url, timeout=t, allow_redirects=True)
        return r
    except Exception as e:
        # caller can log or handle
        return None
