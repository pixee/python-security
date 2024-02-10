from pathlib import Path
import shlex
from glob import glob
from os import get_exec_path
from shutil import which
from subprocess import CompletedProcess
from typing import Union, List, Tuple, TypeAlias, Callable
from security.exceptions import SecurityException

ValidRestrictions: TypeAlias = Union[list[str], tuple[str], set[str], frozenset[str], None]
ValidCommand: TypeAlias = Union[str, list[str]]

DEFAULT_CHECKS = frozenset(
    ("PREVENT_COMMAND_CHAINING", 
     "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES",
     "PREVENT_COMMON_EXPLOIT_EXECUTABLES", 
     "PREVENT_UNCOMMON_PATH_TYPES",
     "PREVENT_ADMIN_OWNED_FILES")
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

BANNED_EXECUTABLES = frozenset(("nc", "netcat", "ncat", "curl", "wget", "dpkg", "rpm"))
BANNED_PATHTYPES = frozenset(
    ("mount", "symlink", "block_device", "char_device", "fifo", "socket"))
BANNED_OWNERS = frozenset(("root", "admin", "wheel", "sudo"))
BANNED_GROUPS = frozenset(("root", "admin", "wheel", "sudo"))
BANNED_COMMAND_CHAINING_SEPARATORS = frozenset(("&", ";", "|", "\n"))
BANNED_PROCESS_SUBSTITUTION_OPERATORS = frozenset(("$(", "`", "<(", ">("))
BANNED_COMMAND_CHAINING_EXECUTABLES = frozenset((
    "eval", "exec", "-exec", "env", "source", "sudo", "su", "gosu", "sudoedit", 
    "bash", "sh", "zsh", "csh", "rsh", "tcsh", "ksh", "dash", "fish", "powershell", "pwsh", "pwsh-preview", "pwsh-lts",
    "xargs", "awk", "perl", "python", "ruby", "php", "lua", "tclsh", "sqlplus",
    "expect", "screen", "tmux", "byobu", "byobu-ugraph", "script", "scriptreplay", "scriptlive",
    "nohup", "at", "batch", "anacron", "cron", "crontab", "systemctl", "service", "init", "telinit",
    "systemd", "systemd-run"
    )

)

def run(original_func: Callable, command: ValidCommand, *args, restrictions: ValidRestrictions=DEFAULT_CHECKS, **kwargs) -> Union[CompletedProcess, None]:
    # If there is a command and it passes the checks pass it the original function call
    if command:
        check(command, restrictions)
        return _call_original(original_func, command, *args, **kwargs)

    # If there is no command, return None
    return None


call = run


def _call_original(original_func: Callable, command: ValidCommand, *args, **kwargs) -> Union[CompletedProcess, None]:
    return original_func(command, *args, **kwargs)


def _parse_command(command: ValidCommand) -> Union[List[str], None]:
    if isinstance(command, str):
        if not command.strip():
            # Empty commands are safe
            return None
        parsed_command = shlex.split(command, comments=True)
    elif isinstance(command, list):
        if not command or command == [""]:
            # Empty commands are safe
            return None
        
        # Join then split with shlex to process shell-like syntax correctly. 
        parsed_command = shlex.split(shlex.join(command), comments=True)
    else:
        raise TypeError("Command must be a str or a list")

    return parsed_command


def _resolve_executable_path(executable: str) -> Union[Path, None]:
    if path := which(executable):
        return Path(path).resolve()

    # Check if the executable is in the system PATH
    for path in get_exec_path():
        if (executable_path := Path(path) / executable).exists():
            return executable_path.resolve()
    
    return None


def _resolve_paths_in_parsed_command(parsed_command: list) -> Tuple[set[Path], set[str]]:
    # Create Path objects and resolve symlinks then add to sets of Path and absolute path strings from the parsed commands
    # for comparison with the sensitive files common exploit executables and group/owner checks.

    abs_paths, abs_path_strings = set(), set()
    # A second shlex split is needed to handle shell-like syntax correctly when wrapped in quotes before globbing
    cmd_parts = [cmd_part for cmd_arg in parsed_command for cmd_part in shlex.split(cmd_arg.strip("'\""))]
    for cmd_part in cmd_parts:
        # check if the cmd_part is an executable and resolve the path
        if executable_path := _resolve_executable_path(cmd_part):
            abs_paths.add(executable_path)
            abs_path_strings.add(str(executable_path))

        # Handle any globbing characters and repeating slashes from the command and resolve symlinks to get absolute path
        for path in glob(cmd_part, include_hidden=True, recursive=True): 
            path = Path(path)

            # When its a symlink both the absolute path of the symlink 
            # and the resolved path of its target are added to the sets
            if path.is_symlink(): 
                path = path.absolute()
                abs_paths.add(path)
                abs_path_strings.add(str(path))
            
            abs_path = Path(path).resolve()
            abs_paths.add(abs_path)
            abs_path_strings.add(str(abs_path))

            # Check if globbing returned an executable and add to the sets    
            if executable_path := _resolve_executable_path(str(path)):
                abs_paths.add(executable_path)
                abs_path_strings.add(str(executable_path))

            # Check if globbing returned a directory and add all files in the directory to the sets
            if abs_path.is_dir():
                for file in abs_path.rglob("*"):
                    file = file.resolve()
                    abs_paths.add(file)
                    abs_path_strings.add(str(file))


    return abs_paths, abs_path_strings


def check(command: ValidCommand, restrictions: ValidRestrictions) -> None:
    if not restrictions or (parsed_command := _parse_command(command)) is None:
        # No restrictions or commands, no checks
        return None
    
    executable = parsed_command[0]
    executable_path = _resolve_executable_path(executable)

    abs_paths, abs_path_strings = _resolve_paths_in_parsed_command(parsed_command)
    
    if "PREVENT_COMMAND_CHAINING" in restrictions:
        check_multiple_commands(command, parsed_command)

    if "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES" in restrictions:
        check_sensitive_files(command, abs_path_strings)

    if "PREVENT_COMMON_EXPLOIT_EXECUTABLES" in restrictions:
        check_banned_executable(command, abs_paths)

    for path in abs_paths:
        if "PREVENT_UNCOMMON_PATH_TYPES" in restrictions:
            # to avoid blocking the executable itself since most are symlinks to the actual executable
            if path != executable_path:
                check_path_type(path)

        if "PREVENT_ADMIN_OWNED_FILES" in restrictions:
            # to avoid blocking the executable itself since most owned by root or admin and group is wheel or sudo
            if path != executable_path:
                check_file_owner(path)
                check_file_group(path)


def _do_check_multiple_commands(part: str) -> None:
    if any(sep in part for sep in BANNED_COMMAND_CHAINING_SEPARATORS):
        raise SecurityException(f"Multiple commands not allowed. Separators found.")

    if any(sep in part for sep in BANNED_PROCESS_SUBSTITUTION_OPERATORS):
        raise SecurityException(f"Multiple commands not allowed. Process substitution operators found.")

    if part.strip() in BANNED_COMMAND_CHAINING_EXECUTABLES:
        raise SecurityException(f"Multiple commands not allowed. Executable {part} allows command chaining.")


def check_multiple_commands(command: ValidCommand, parsed_command: list) -> None:    
    if isinstance(command, str):
        _do_check_multiple_commands(command.strip())
        
    if isinstance(command, list):
        for cmd_arg in command:
            _do_check_multiple_commands(cmd_arg)

    for cmd_arg in parsed_command:
        _do_check_multiple_commands(cmd_arg)


def check_sensitive_files(command: ValidCommand, abs_path_strings: set[str]) -> None:
    for sensitive_path in SENSITIVE_FILE_NAMES:
        if (sensitive_path in command 
            or sensitive_path in abs_path_strings
            or any(str(path).endswith(sensitive_path) for path in abs_path_strings)):
            raise SecurityException(
                "Disallowed access to sensitive file: " + sensitive_path)


def check_banned_executable(command: ValidCommand, abs_paths: set[Path]) -> None:
    for banned_executable in BANNED_EXECUTABLES:
        if (any(str(path).endswith(banned_executable) for path in abs_paths)
            or (isinstance(command, str) 
                and (command.startswith(f"{banned_executable} ") 
                     or f"bin/{banned_executable}" in command 
                     or f" {banned_executable} " in command )
            )
            or (isinstance(command, list) 
                and any(
                    (part.strip("'\"").startswith(f"{banned_executable} ")
                    or f"bin/{banned_executable}" in part 
                    or f" {banned_executable} " in part
                    ) for part in command)
                )
            ):
            raise SecurityException(
                f"Disallowed command: {banned_executable}")



def check_path_type(path: Path) -> None:
    for pathtype in BANNED_PATHTYPES:
        if getattr(path, f"is_{pathtype}")():
            raise SecurityException(f"Disallowed access to path type {pathtype}: {path}")


def check_file_owner(path: Path) -> None:
    owner = path.owner()
    if owner in BANNED_OWNERS:
        raise SecurityException(
            f"Disallowed access to file owned by {owner}: {path}")


def check_file_group(path: Path) -> None:
    group = path.group()
    if group in BANNED_GROUPS:
        raise SecurityException(
            f"Disallowed access to file owned by {group}: {path}")
