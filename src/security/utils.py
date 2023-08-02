def strip_all_newlines(value):
    """Remove all newline chars from anywhere in `value`"""
    if not isinstance(value, (str, bytes, bytearray)):
        return value
    if isinstance(value, str):
        return value.replace("\n", "").replace("\r", "")
    if isinstance(value, (bytes, bytearray)):
        return value.replace(b"\n", b"").replace(b"\r", b"")
