import urllib.request
from urllib.parse import urlparse


ALLOWED = {"api.internal", "cdn.internal"}


def fetch(url):
    host = urlparse(url).hostname or ""
    if host not in ALLOWED:
        raise ValueError("host not allowed")
    with urllib.request.urlopen(url) as resp:
        return resp.read()
