import shlex
from re import compile as re_compile
from pathlib import Path
from glob import iglob
from os import getenv, get_exec_path, access, X_OK
from os.path import expanduser, expandvars
from shutil import which
from subprocess import CompletedProcess
from typing import Union, Optional, List, Tuple, Set, FrozenSet, Sequence, Callable, Iterator
from security.exceptions import SecurityException

ValidRestrictions = Optional[Union[FrozenSet[str], Sequence[str]]]
ValidCommand = Union[str, List[str]]

DEFAULT_CHECKS = frozenset(
    ("PREVENT_COMMAND_CHAINING",
     "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES",
     "PREVENT_COMMON_EXPLOIT_EXECUTABLES",
     )
)

SENSITIVE_FILE_PATHS = frozenset(
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

BANNED_EXECUTABLES = frozenset(
    ("nc", "netcat", "ncat", "curl", "wget", "dpkg", "rpm"))
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
))


SHELL_VARIABLE_REGEX = re_compile(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)')
SHELL_EXPANSION_REGEX = re_compile(r'(([\$\S])*(\{[^{}]+?\})[^\s\$]*)')
REDIRECTION_OPERATORS_REGEX = re_compile(r'(?!<\()(<<?<?[-&]?[-&p]?|(?:\d+|&)?>>?&?-?(?:\d+|\|)?|<>)')


def run(original_func: Callable, command: ValidCommand, *args, restrictions: ValidRestrictions = DEFAULT_CHECKS, **kwargs) -> Union[CompletedProcess, None]:
    # If there is a command and it passes the checks pass it the original function call
    check(command, restrictions)
    return _call_original(original_func, command, *args, **kwargs)


call = run


def _call_original(original_func: Callable, command: ValidCommand, *args, **kwargs) -> Union[CompletedProcess, None]:
    return original_func(command, *args, **kwargs)


def _get_env_var_value(var: str) -> str:
    if (expanded_var := expandvars(var)) != var:
        return expanded_var
    elif (expanded_var := getenv(var)):
        return expanded_var
    else:
        return ""


def _shell_expand(command: str) -> str:
    # Handles simple shell variable expansion like $HOME, $PWD, $IFS
    for match in SHELL_VARIABLE_REGEX.finditer(command):
        shell_var_str = match.group(0)
        var = shell_var_str[1:]
        value = _get_env_var_value(var)       
        
        # Explicitly set IFS to space if it is empty since IFS is not always returned by expandvars or getenv on all systems
        if var == "IFS" and not value:
                value = " "

        command = command.replace(shell_var_str, value)

    # Handle Complex Parameter, Brace and Sequence shell expansions 
    for match in SHELL_EXPANSION_REGEX.finditer(command):
        full_expansion, prefix, brackets = match.groups()
        inside_brackets = brackets[1:-1]
        
        if prefix == "$":
            # Handles Parameter expansion like ${var:-defaultval}, ${var:=defaultval}, ${var:+defaultval}, ${var:?defaultval}
            var, *expansion_params = inside_brackets.split(":")
            
            value, operation, default = "", "", ""
            start_slice, end_slice = None, None
            if expansion_params:
                expansion_param_1 = expansion_params.pop(0)
                first_char = expansion_param_1[0]
                if first_char.isdigit() or (first_char == "-" and expansion_param_1[1:].isdigit()):
                    start_slice = int(expansion_param_1)
                    if expansion_params:
                        expansion_param_2 = expansion_params[0]
                        end_slice = int(expansion_param_2)
                else:
                    operation = first_char
                    default = expansion_param_1[1:]

            value = _get_env_var_value(var)
            if start_slice is not None:
                value = value[start_slice:end_slice]
            elif not operation or operation == "?":
                value = value
            elif operation in "-=":
                value = value or default
            elif operation == "+":
                value = default if value else ""
            
            # Explicitly set IFS to space but only after checking for a default value
            if var == "IFS" and not value:
                value = " "

            command = command.replace(f"${brackets}", value)
            
        else:
            # Handles Brace and sequence expansion like {1..10..2}, {a,b,c}, {1..10}, {1..-1}
            values = []           
            if (',' not in inside_brackets 
                and len(inside_params := inside_brackets.split('..')) in (2,3)
                and all(param.isdigit() or param.startswith("-") for param in inside_params)
                ):
                
                # Sequence expansion
                inside_params = list(map(int, inside_params))
                if len(inside_params) == 2:
                    inside_params.append(1)
                start, end, step = inside_params
                
                sequence = None
                if start <= end and step > 0:
                    sequence = range(start, end+1, step)   
                elif start <= end and step < 0:
                    sequence = range(end-1, start-1, step)   
                elif start > end and step > 0:
                    sequence = range(start, end-1, -step)   
                elif start > end and step < 0:
                    sequence = reversed(range(start, end-1, step))   

                if sequence:
                    for i in sequence:
                        values.append(full_expansion.replace(brackets, str(i)))
                else:
                    values.append(full_expansion.replace(brackets, inside_brackets))
                
            else:
                # Brace expansion
                for var in inside_brackets.split(','):
                    var = var.strip("\"'")
                    if var.startswith("$"):
                        var_value = _get_env_var_value(var)
                    else:
                        var_value = var
                    values.append(full_expansion.replace(brackets, var_value, 1))
            
            value = ' '.join(values)
            command = command.replace(full_expansion, value)

    return command


def _space_redirects(command: str) -> str:
    # Space out redirect operators to avoid them being combined with the next or previous command part when splitting
    return REDIRECTION_OPERATORS_REGEX.sub(r' \1 ', command)


def _recursive_shlex_split(command: str) -> Iterator[str]:
    for cmd_part in shlex.split(command, comments=True):
        yield cmd_part

        # Strip either type of quotes but not both
        if cmd_part.startswith("'") and cmd_part.endswith("'"):
            cmd_part = cmd_part.strip("'")
        elif cmd_part.startswith('"') and cmd_part.endswith('"'):
            cmd_part = cmd_part.strip('"')

        if '"' in cmd_part or "'" in cmd_part or " " in cmd_part:
            yield from _recursive_shlex_split(cmd_part)
        

def _parse_command(command: ValidCommand) -> Optional[Tuple[str, List[str]]]:
    if isinstance(command, str):
        if not command.strip():
            # Empty commands are safe
            return None
        
        command_str = command
    elif isinstance(command, list):
        if not command or command == [""]:
            # Empty commands are safe
            return None
        
        command_str = " ".join(command)
    else:
        raise TypeError("Command must be a str or a list")

    spaced_command = _space_redirects(command_str)
    expanded_command = _shell_expand(spaced_command)
    parsed_command = list(_recursive_shlex_split(expanded_command))
    return expanded_command, parsed_command


def _path_is_executable(path: Path) -> bool:
    return access(path, X_OK)


def _resolve_executable_path(executable: str) -> Union[Path, None]:
    if executable_path := which(executable):
        return Path(executable_path).resolve()

    # Explicitly check if the executable is in the system PATH when which fails
    for path in get_exec_path():
        if (executable_path := Path(path) / executable).exists() and _path_is_executable(executable_path):
            return executable_path.resolve()

    return None


def _resolve_paths_in_parsed_command(parsed_command: List[str]) -> Tuple[Set[Path], Set[str]]:
    # Create Path objects and resolve symlinks then add to sets of Path and absolute path strings from the parsed commands
    # for comparison with the sensitive files common exploit executables and group/owner checks.

    abs_paths, abs_path_strings = set(), set()

    for cmd_part in parsed_command:
        # check if the cmd_part is an executable and resolve the path
        if executable_path := _resolve_executable_path(cmd_part):
            abs_paths.add(executable_path)
            abs_path_strings.add(str(executable_path))

        # Handle any globbing characters and repeating slashes from the command and resolve symlinks to get absolute path
        for path in iglob(cmd_part, recursive=True):
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

            # Check if globbing and/or resolving symlinks returned an executable and add to the sets
            if executable_path := _resolve_executable_path(str(path)):
                abs_paths.add(executable_path)
                abs_path_strings.add(str(executable_path))

            # Check if globbing and/or resolving symlinks returned a directory and add all files in the directory to the sets
            if abs_path.is_dir():
                for file in abs_path.rglob("*"):
                    file = file.resolve()
                    abs_paths.add(file)
                    abs_path_strings.add(str(file))

    return abs_paths, abs_path_strings


def check(command: ValidCommand, restrictions: ValidRestrictions) -> None:
    if not restrictions:
        # No restrictions no checks
        return None
    
    expanded_command, parsed_command = _parse_command(command) or ("", [])
    if not parsed_command:
        # Empty commands are safe
        return None

    executable = parsed_command[0]
    executable_path = _resolve_executable_path(executable)

    abs_paths, abs_path_strings = _resolve_paths_in_parsed_command(parsed_command)

    if "PREVENT_COMMAND_CHAINING" in restrictions:
        check_multiple_commands(expanded_command, parsed_command)

    if "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES" in restrictions:
        check_sensitive_files(expanded_command, abs_path_strings)

    if "PREVENT_COMMON_EXPLOIT_EXECUTABLES" in restrictions:
        check_banned_executable(expanded_command, abs_path_strings)

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


def check_multiple_commands(expanded_command: str, parsed_command: List[str]) -> None:
    # Since shlex.split removes newlines from the command, it would not be present in the parsed_command and
    # must be checked for in the expanded command string 
    if '\n' in expanded_command:
        raise SecurityException(
            "Multiple commands not allowed. Newline found.")

    for cmd_part in parsed_command:
        if any(seperator in cmd_part for seperator in BANNED_COMMAND_CHAINING_SEPARATORS):
            raise SecurityException(
                f"Multiple commands not allowed. Separators found.")

        if any(substitution_op in cmd_part for substitution_op in BANNED_PROCESS_SUBSTITUTION_OPERATORS):
            raise SecurityException(
                f"Multiple commands not allowed. Process substitution operators found.")

        if cmd_part.strip() in BANNED_COMMAND_CHAINING_EXECUTABLES:
            raise SecurityException(
                f"Multiple commands not allowed. Executable {cmd_part} allows command chaining.")


def check_sensitive_files(expanded_command: str, abs_path_strings: Set[str]) -> None:
    for sensitive_path in SENSITIVE_FILE_PATHS:
        # First check the absolute path strings for the sensitive files
        # Then handle edge cases when a sensitive file is part of a command but the path could not be resolved
        if (
            any(abs_path_string.endswith(sensitive_path)
                for abs_path_string in abs_path_strings)
            or sensitive_path in expanded_command
        ):
            raise SecurityException(
                f"Disallowed access to sensitive file: {sensitive_path}")


def check_banned_executable(expanded_command: str, abs_path_strings: Set[str]) -> None:
    for banned_executable in BANNED_EXECUTABLES:
        # First check the absolute path strings for the banned executables
        # Then handle edge cases when a banned executable is part of a command but the path could not be resolved
        if (
            any((abs_path_string.endswith(
                f"/{banned_executable}") for abs_path_string in abs_path_strings))
            or expanded_command.startswith(f"{banned_executable} ")
            or f"bin/{banned_executable}" in expanded_command
            or f" {banned_executable} " in expanded_command
        ):
            raise SecurityException(
                f"Disallowed command: {banned_executable}")


def check_path_type(path: Path) -> None:
    for pathtype in BANNED_PATHTYPES:
        if getattr(path, f"is_{pathtype}")():
            raise SecurityException(
                f"Disallowed access to path type {pathtype}: {path}")


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


