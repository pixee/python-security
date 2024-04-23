from urllib.parse import urlparse
from urllib.request import urlopen as unsafe_urlopen

from requests import get as unsafe_get
from requests import post as unsafe_post

from security.exceptions import SecurityException

from .host_validators import DefaultHostValidator

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

    def check(self, allowed_protocols, host_validator):
        self._check_protocol(allowed_protocols)
        self._check_host(host_validator)

    def _check_protocol(self, allowed_protocols):
        if self.protocol not in allowed_protocols:
            raise SecurityException("Disallowed protocol: %s", self.protocol)

    def _check_host(self, host_validator):
        if not host_validator(self.host).is_allowed:
            raise SecurityException("Disallowed host: %s", self.host)


def urlopen(
    url,
    data=None,
    timeout=None,
    *args,
    allowed_protocols=DEFAULT_PROTOCOLS,
    host_validator=DefaultHostValidator,
    **kwargs,
):
    UrlParser(url).check(allowed_protocols, host_validator)
    return unsafe_urlopen(url, data, timeout, *args, **kwargs)


def get(
    url,
    params=None,
    allowed_protocols=DEFAULT_PROTOCOLS,
    host_validator=DefaultHostValidator,
    **kwargs,
):
    UrlParser(url).check(allowed_protocols, host_validator)
    return unsafe_get(url, params=params, **kwargs)


def post(
    url,
    data=None,
    json=None,
    allowed_protocols=DEFAULT_PROTOCOLS,
    host_validator=DefaultHostValidator,
    **kwargs,
):
    UrlParser(url).check(allowed_protocols, host_validator)
    return unsafe_post(url, data=data, json=json, **kwargs)
