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

BANNED_EXECUTABLES = frozenset(("nc", "curl", "wget", "dpkg", "rpm"))


def run(original_func, command, *args, restrictions=DEFAULT_CHECKS, **kwargs):
    check(command, restrictions)
    return _call_original(original_func, command, *args, **kwargs)


call = run


def _call_original(original_func, command, *args, **kwargs):
    return original_func(command, *args, **kwargs)


def check(command, restrictions):
    assert isinstance(command, (str, list))

    if isinstance(command, str):
        if not command.strip():
            # Empty commands are safe
            return
        parsed_command = shlex.split(command, comments=True)
    if isinstance(command, list):
        if not command:
            # Empty commands are safe
            return
        parsed_command = command

    if "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES" in restrictions:
        check_sensitive_files(parsed_command)

    if "PREVENT_COMMAND_CHAINING" in restrictions:
        check_multiple_commands(command)

    if "PREVENT_COMMON_EXPLOIT_EXECUTABLES" in restrictions:
        check_banned_executable(parsed_command)


def check_sensitive_files(parsed_command: list):
    for cmd in parsed_command:
        path = Path(cmd)
        if any(str(path).endswith(sensitive) for sensitive in SENSITIVE_FILE_NAMES):
            raise SecurityException("Disallowed access to sensitive file: %s", cmd)


def check_multiple_commands(command: str):
    separators = ["&", ";", "|", "\n"]
    if isinstance(command, str):
        stripped = command.strip()
        if any(sep in stripped for sep in separators):
            raise SecurityException("Multiple commands not allowed: %s", command)

    if isinstance(command, list):
        if any(cmd in separators for cmd in command):
            raise SecurityException("Multiple commands not allowed: %s", command)


def check_banned_executable(parsed_command: list):
    if any(cmd in BANNED_EXECUTABLES for cmd in parsed_command):
        raise SecurityException("Disallowed command: %s", parsed_command)
