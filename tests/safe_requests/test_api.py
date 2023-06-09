import pytest
from security.exceptions import SecurityException
from security.safe_requests import get


class TestSafeRequestApi:
    @pytest.mark.parametrize("protocol", ["http", "https"])
    def test_url_default_safe_protocols(self, protocol):
        r = get(f"{protocol}://httpbin.org/basic-auth/user/pass")
        assert r is not None

    def test_url_unsafe_protocol(self):
        with pytest.raises(SecurityException):
            get("ftp://example.com/file.txt")

    def test_url_safe_protocol_allowed(self):
        r = get("ftp://example.com/file.txt", allowed_protocols=("ftp",))
        assert r is not None
