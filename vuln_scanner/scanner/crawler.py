from collections import deque
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

ALLOWED_SCHEMES = {"http", "https"}

def same_origin(url: str, base: str) -> bool:
    try:
        u = urlparse(url)
        b = urlparse(base)
        return u.scheme in ALLOWED_SCHEMES and u.netloc == b.netloc
    except Exception:
        return False

def extract_links(html: str, base_url: str):
    """Extract absolute links from HTML limited to http/https."""
    links = set()
    try:
        soup = BeautifulSoup(html or "", "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href")
            if not href:
                continue
            abs_url = urljoin(base_url, href)
            pu = urlparse(abs_url)
            if pu.scheme in ALLOWED_SCHEMES:
                links.add(abs_url.split("#")[0])  # drop fragments
    except Exception:
        pass
    return links

def crawl(session, start_url: str, max_depth: int = 1, max_pages: int = 50, timeout: int = 10):
    """
    Simple breadth-first crawler limited to same origin.
    Returns a list of discovered page URLs including the start_url.
    """
    visited = set()
    order = []
    q = deque()
    q.append((start_url, 0))
    base = start_url
    while q and len(order) < max_pages:
        url, depth = q.popleft()
        if url in visited:
            continue
        visited.add(url)
        order.append(url)
        if depth >= max_depth:
            continue
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            html = r.text if r else ""
        except Exception:
            html = ""
        for link in extract_links(html, url):
            if link not in visited and same_origin(link, base):
                q.append((link, depth + 1))
                if len(visited) + len(q) >= max_pages:
                    break
    return order
