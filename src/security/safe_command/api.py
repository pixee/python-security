from pathlib import Path
import shlex
from security.exceptions import SecurityException

DEFAULT_CHECKS = frozenset(
    ("PREVENT_COMMAND_CHAINING", "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES")
)
SENSITIVE_FILE_NAMES = frozenset(
    (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sysconfig/network",
        "/etc/network/interfaces",
        "/etc/resolv.conf",
        "/etc/sudoers",
        "/etc/hosts",
    )
)


def run(original_func, command, *args, restrictions=DEFAULT_CHECKS, **kwargs):
    check(command, restrictions)
    return original_func(command, *args, **kwargs)


def check(command, restrictions):
    assert isinstance(command, (str, list))

    if isinstance(command, str):
        if not command.strip():
            # Empty commands are safe
            return
        parsed_command = shlex.split(command)
    if isinstance(command, list):
        if not command:
            # Empty commands are safe
            return
        parsed_command = command

    if "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES" in restrictions:
        check_sensitive_files(parsed_command)


def check_sensitive_files(parsed_command: list):
    for cmd in parsed_command:
        path = Path(cmd)
        if any(str(path).endswith(sensitive) for sensitive in SENSITIVE_FILE_NAMES):
            raise SecurityException("Disallowed access to sensitive file: %s", cmd)
