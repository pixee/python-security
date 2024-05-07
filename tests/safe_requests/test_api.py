import pytest

from security.exceptions import SecurityException
from security.safe_requests import get, post
from security.safe_requests.host_validators import DefaultHostValidator


@pytest.mark.parametrize(
    "method_name",
    [
        get,
        post,
    ],
)
class TestSafeRequestApi:
    @pytest.mark.parametrize("protocol", ["http", "https"])
    def test_url_default_safe_protocols(self, protocol, method_name):
        r = method_name(f"{protocol}://httpbin.org/basic-auth/user/pass")
        assert r is not None

    def test_url_unsafe_protocol(self, method_name):
        with pytest.raises(SecurityException):
            method_name("ftp://example.com/file.txt")

    def test_url_safe_protocol_allowed(self, method_name):
        r = method_name("ftp://example.com/file.txt", allowed_protocols=("ftp",))
        assert r is not None

    @pytest.mark.parametrize("host", DefaultHostValidator.KNOWN_INFRASTRUCTURE_HOSTS)
    def test_unsafe_host(self, host, method_name):
        with pytest.raises(SecurityException):
            method_name(f"http://{host}/user-data/")
