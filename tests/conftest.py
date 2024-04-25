import mock
import pytest


@pytest.fixture(autouse=True, scope="module")
def disable_external_requests():
    """
    Unit tests should not make external requests while testing requests.
    """
    patch_request = mock.patch("requests.sessions.Session.request")
    patch_request.start()
    yield
    patch_request.stop()
