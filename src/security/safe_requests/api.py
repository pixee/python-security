from security.exceptions import SecurityException
from requests import get as unsafe_get
from urllib.parse import urlparse

DEFAULT_PROTOCOLS = frozenset(("http", "https"))


def get(url, params=None, allowed_protocols=DEFAULT_PROTOCOLS, **kwargs):
    _check_protocol(url, allowed_protocols)
    return unsafe_get(url, params=params, **kwargs)


def _check_protocol(url, allowed_protocols):
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme

    if protocol not in allowed_protocols:
        raise SecurityException("Disallowed protocol: %s", protocol)
