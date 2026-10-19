import urllib.request


def fetch(url):
    with urllib.request.urlopen(url) as resp:
        return resp.read()
