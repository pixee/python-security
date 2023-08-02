import pytest
from security import strip_all_newlines


class TestStripAllNewlines:
    @pytest.mark.parametrize(
        "input_val,expected",
        [
            (True, True),
            (Exception, Exception),
            (None, None),
            (b"\nhello", b"hello"),
            ("\nhel\nlo\n", "hello"),
            ("\nhel\r\nlo\n", "hello"),
            (bytearray([2, 3, 5, 7]), bytearray([2, 3, 5, 7])),
            ("\n\r\n\n", ""),
            ("", ""),
        ],
    )
    def test_strip_all_newlines(self, input_val, expected):
        assert strip_all_newlines(input_val) == expected
