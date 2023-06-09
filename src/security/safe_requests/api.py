from .host_validators import DefaultHostValidator
from security.exceptions import SecurityException
from requests import get as unsafe_get
from urllib.parse import urlparse

DEFAULT_PROTOCOLS = frozenset(("http", "https"))


class UrlParser:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)

    @property
    def protocol(self):
        return self.parsed_url.scheme

    @property
    def host(self):
        return self.parsed_url.netloc


def get(
    url,
    params=None,
    allowed_protocols=DEFAULT_PROTOCOLS,
    host_validator=DefaultHostValidator,
    **kwargs,
):
    parsed_url = UrlParser(url)
    _check_protocol(parsed_url.protocol, allowed_protocols)
    _check_host(parsed_url.host, host_validator)
    return unsafe_get(url, params=params, **kwargs)


def _check_protocol(protocol, allowed_protocols):
    if protocol not in allowed_protocols:
        raise SecurityException("Disallowed protocol: %s", protocol)


def _check_host(host, host_validator):
    if not host_validator(host).is_allowed:
        raise SecurityException("Disallowed host: %s", host)
