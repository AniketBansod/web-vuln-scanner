# scanner/input_handler.py
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

def validate_url(url: str) -> bool:
    """Basic URL validation."""
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

def parse_url_params(url: str):
    """
    Return (parsed_url_object, params_dict)
    parsed_url_object is result of urllib.parse.urlparse
    params_dict is mapping of query parameter -> value
    """
    from urllib.parse import urlparse, parse_qsl
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return parsed, qs

def build_url_with_params(parsed, params: dict) -> str:
    """Rebuild URL with modified params dictionary."""
    from urllib.parse import urlencode, urlunparse
    q = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))
