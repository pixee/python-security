import pytest
import subprocess
from pathlib import Path
from os import mkfifo, symlink, remove
from shutil import rmtree, which

from security import safe_command
from security.safe_command.api import _parse_command, _resolve_paths_in_parsed_command, _shell_expand
from security.exceptions import SecurityException

with (Path(__file__).parent / "fuzzdb" / "command-injection-template.txt").open() as f:
    FUZZDB_OS_COMMAND_INJECTION_PAYLOADS = [line.replace('\\n','\n').replace("\\'", "'")[:-1] for line in f] # Remove newline
with (Path(__file__).parent / "fuzzdb" / "traversals-8-deep-exotic-encoding.txt").open() as f:
    FUZZDB_PATH_TRAVERSAL_PAYLOADS = [line.replace('\\n','\n').replace("\\'", "'")[:-1] for line in f] # Remove newline


@pytest.fixture
def setup_teardown(tmpdir):
    # Working directory is the tmpdir
    wd = Path(tmpdir)
    wd.mkdir(exist_ok=True)

    # Create some files and directories to use in the tests
    testtxt = wd / "test.txt"
    testtxt.write_text("USERDATA1\nUSERDATA2\nUSERDATA3\n")
    test2txt = wd / "test2.txt"
    test2txt.write_text("USERDATA4\nUSERDATA5\nUSERDATA6\n")
    rglob_testdir = wd / "rglob_testdir"
    rglob_testdir.mkdir()
    rglob_testfile = rglob_testdir / "rglob_testfile.txt"
    rglob_testfile.touch()
    space_in_name = wd / "space in name.txt"
    space_in_name.touch()

    testtxt.touch()
    test2txt.touch()
    cwd_testfile = Path("./cwdtest.txt").resolve()
    cwd_testfile.touch()
    fifo_testfile = (wd / "fifo_testfile").resolve()
    mkfifo(fifo_testfile)
    symlink_testfile = (wd / "symlink_testfile").resolve()
    symlink(cwd_testfile, symlink_testfile) # Target of symlink_testfile is cwd_testfile.txt
    passwd = Path("/etc/passwd").resolve()
    sudoers = Path("/etc/sudoers").resolve()
    # Get Path objects for the test commands
    cat, echo, grep, nc, curl, sh = map(lambda cmd: Path(which(cmd) or f"/usr/bin/{cmd}" ), ["cat", "echo", "grep", "nc", "curl", "sh"]) 
    testpaths = {
        "wd": wd,
        "test.txt": testtxt,
        "test2.txt": test2txt,
        "rglob_testdir": rglob_testdir,
        "rglob_testfile": rglob_testfile,
        "space_in_name": space_in_name,
        "cwd_testfile": cwd_testfile,
        "fifo_testfile": fifo_testfile,
        "symlink_testfile": symlink_testfile,
        "passwd": passwd,
        "sudoers": sudoers,
        "cat": cat,
        "echo": echo,
        "grep": grep,
        "nc": nc,
        "curl": curl,
        "sh": sh
    }
    yield testpaths
    
    # Clean up the test files and directories
    rmtree(tmpdir, ignore_errors=True)
    remove(cwd_testfile)
    

def insert_testpaths(command, testpaths):
    """Replace placeholders in the command or expected result with the test paths"""
    if isinstance(command, str):
        for k, v in testpaths.items():
            command = command.replace(f"{{{k}}}", str(v))
    elif isinstance(command, list):
        for i, cmd_part in enumerate(command):
            command[i] = insert_testpaths(cmd_part, testpaths)
    return command


class TestSafeCommandInternals:
    @pytest.mark.parametrize(
        "str_cmd, list_cmd, expected_parsed_command",
        [
            ("whoami", ["whoami"], ["whoami"]),
            ("ls -l", ["ls", "-l"], ["ls", "-l"]),
            ("ls -l -a", ["ls", "-l", "-a"], ["ls", "-l", "-a"]),
            ("grep 'test' 'test.txt'", ["grep", "'test'", "'test.txt'"], ["grep", "test", "test.txt"]),
            ("grep test test.txt", ["grep", "test", "test.txt"], ["grep", "test", "test.txt"]),
            ("grep -e 'test test' 'test.txt'", ["grep", "-e", "'test test'", "'test.txt'"], ["grep", "-e", "test test", "test", "test", "test.txt"]),
            ("echo 'test1 test2 test3' > test.txt", ["echo", "'test1 test2 test3'", ">", "test.txt"], ['echo', 'test1 test2 test3', 'test1', 'test2', 'test3', '>', 'test.txt']),
            ('echo "test1 test2 test3" > test.txt', ["echo", '"test1 test2 test3"', ">", "test.txt"], ['echo', 'test1 test2 test3', 'test1', 'test2', 'test3', '>', 'test.txt']), 
            ("echo test1 test2 test3 > test.txt", ["echo", "test1", "test2", "test3", ">", "test.txt"], ["echo", "test1", "test2", "test3", ">", "test.txt"]),
        ]
    )
    def test_parse_command(self, str_cmd, list_cmd, expected_parsed_command, setup_teardown):
        expanded_str_cmd, parsed_str_cmd = _parse_command(str_cmd)
        expanded_list_cmd, parsed_list_cmd = _parse_command(list_cmd)
        assert expanded_str_cmd == expanded_list_cmd
        assert parsed_str_cmd == parsed_list_cmd == expected_parsed_command


    @pytest.mark.parametrize(
        "command, expected_paths",
        [
            ("echo HELLO", {"echo"}),
            ("cat cwdtest.txt", {"cat", "cwd_testfile"}),
            ("cat ./cwdtest.txt", {"cat", "cwd_testfile"}),
            ("cat cwd*.txt", {"cat", "cwd_testfile"}),
            ("cat {test.txt}", {"cat", "test.txt"}),
            ("cat '{test.txt}' ", {"cat", "test.txt"}),
            ('cat "{test.txt}" ', {"cat", "test.txt"}),
            ("cat {test.txt} {test2.txt}", {"cat", "test.txt", "test2.txt"}),
            # Check globbing and multiple slashes
            ("cat {wd}/*t.txt {wd}/test?.txt", {"cat", "test.txt", "test2.txt"}),
            ("cat {wd}///////*t.txt", {"cat", "test.txt"}),
            # Check globbing in executable path
            ("/bin/c*t '{test.txt}' ", {"cat", "test.txt"}),
            # Check that /etc or /private/etc for mac handling is correct
            ("cat /etc/passwd /etc/sudoers ", {"cat", "passwd", "sudoers"}),
            ("/bin/cat /etc/passwd", {"cat", "passwd"}),
            # Check fifo and symlink
            ("cat {fifo_testfile}", {"cat", "fifo_testfile"}),
            # Symlink should resolve to cwdtest.txt so should get the symlink and the target
            ("cat {symlink_testfile}", {"cat", "symlink_testfile", "cwd_testfile"},), 
            # Check a command with binary name as an argument
            ("echo 'cat' {test.txt}", {"echo", "cat", "test.txt"}),
            # Command has a directory so should get the dir and all the subfiles and resolved symlink to cwdtest.txt
            ("grep 'cat' -r {rglob_testdir}", {"grep", "cat", "rglob_testdir", "rglob_testfile"}),
            ("nc -l -p 1234", {"nc"}),
            ("curl https://example.com", {"curl"}),
            ("sh -c 'curl https://example.com'", {"sh", "curl"}),
            ("cat '{space_in_name}'", {"cat", "space_in_name"}),
        ] 
    )
    def test_resolve_paths_in_parsed_command(self, command, expected_paths, setup_teardown):
        testpaths = setup_teardown
        command = insert_testpaths(command, testpaths)
        expected_paths = {testpaths[p] for p in expected_paths}

        expanded_command, parsed_command = _parse_command(command)
        abs_paths, abs_path_strings = _resolve_paths_in_parsed_command(parsed_command)
        assert abs_paths == expected_paths
        assert abs_path_strings == {str(p) for p in expected_paths}

    @pytest.mark.parametrize(
        "string, expanded_str",
        [
            ("echo $HOME", f"echo {str(Path.home())}"),
            ("echo $PWD", f"echo {Path.cwd()}"),
            ("echo $IFS", "echo  "),

            ("echo $HOME $PWD $IFS", f"echo {str(Path.home())} {Path.cwd()}  "),    
            ("echo ${HOME} ${PWD} ${IFS}", f"echo {str(Path.home())} {Path.cwd()}  "),        

            ("echo ${IFS}", "echo  "),
            ("echo ${IFS:0}", "echo  "),
            ("echo ${IFS:0:1}", "echo  "),
            ("echo ${IFS:4:20}", "echo  "),
            ("echo ${HOME:4:20}", f"echo {str(Path.home())[4:20]}"),
            ("echo ${HOME:4}", f"echo {str(Path.home())[4:]}"),
            ("echo ${HOME:-1:-10}", f"echo {str(Path.home())[-1:10]}"),
            
            ("echo ${HOME:-defaultval}", f"echo {str(Path.home())}"),
            ("echo ${HOME:=defaultval}", f"echo {str(Path.home())}"),
            ("echo ${HOME:+defaultval}", "echo defaultval"),

            ("echo ${BADKEY:-defaultval}", "echo defaultval"),
            ("echo ${BADKEY:=defaultval}", "echo defaultval"),
            ("echo ${BADKEY:+defaultval}", "echo "),
            ("echo ${BADKEY:0:2}", "echo "),

            ("echo a{d,c,b}e", "echo ade ace abe"),
            ("echo a{'d',\"c\",b}e", "echo ade ace abe"),
            ("echo a{$HOME,$PWD,$IFS}e", f"echo a{str(Path.home())}e a{Path.cwd()}e a e"),
            
            ("echo {1..-1}", "echo 1 0 -1"),
            ("echo {1..1}", "echo 1"),
            ("echo {1..4}", "echo 1 2 3 4"),

            ("echo {1..10..2}", "echo 1 3 5 7 9"),
            ("echo {1..10..-2}", "echo 9 7 5 3 1"),
            ("echo {10..1..2}", "echo 10 8 6 4 2"),
            ("echo {10..1..-2}", "echo 2 4 6 8 10"),

            ("echo {-1..10..2}", "echo -1 1 3 5 7 9"),
            ("echo {-1..10..-2}", "echo 9 7 5 3 1 -1"),
            ("echo {10..-1..2}", "echo 10 8 6 4 2 0"),
            ("echo {10..-1..-2}", "echo 0 2 4 6 8 10"),

            ("echo {1..-10..2}", "echo 1 -1 -3 -5 -7 -9"),
            ("echo {1..-10..-2}", "echo -9 -7 -5 -3 -1 1"),
            ("echo {-10..1..2}", "echo -10 -8 -6 -4 -2 0"),
            ("echo {-10..1..-2}", "echo 0 -2 -4 -6 -8 -10"),

            ("echo {-1..-10..2}", "echo -1 -3 -5 -7 -9"),
            ("echo {-1..-10..-2}", "echo -9 -7 -5 -3 -1"),
            ("echo {-10..-1..2}", "echo -10 -8 -6 -4 -2"),
            ("echo {-10..-1..-2}", "echo -2 -4 -6 -8 -10"),
            ("echo {10..-10..2}", "echo 10 8 6 4 2 0 -2 -4 -6 -8 -10"),
            ("echo {10..-10..-2}", "echo -10 -8 -6 -4 -2 0 2 4 6 8 10"),
            
            ("echo {1..10..0}", "echo 1..10..0"),
            ("echo AB{1..10..0}CD", "echo AB1..10..0CD"),
            ("echo AB{1..$HOME}CD", f"echo AB1..{str(Path.home())}CD"),

            ("echo a{1..4}e", "echo a1e a2e a3e a4e"),
            ("echo AB{1..10..2}CD {$HOME,$PWD} ${BADKEY:-defaultval}", f"echo AB1CD AB3CD AB5CD AB7CD AB9CD {str(Path.home())} {Path.cwd()} defaultval"),
            ("echo AB{1..4}CD", "echo AB1CD AB2CD AB3CD AB4CD"),

            ("find . -name '*.txt' ${BADKEY:--exec} cat {} + ", "find . -name '*.txt' -exec cat {} + "),
        ]
    )
    def test_shell_expansions(self, string, expanded_str, setup_teardown):
        assert _shell_expand(string) == expanded_str


@pytest.mark.parametrize("original_func", [subprocess.run, subprocess.call])
class TestSafeCommandRestrictions:
    EXCEPTIONS = {
    "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES": SecurityException("Disallowed access to sensitive file"),
    "PREVENT_COMMAND_CHAINING": SecurityException("Multiple commands not allowed"),
    "PREVENT_COMMON_EXPLOIT_EXECUTABLES": SecurityException("Disallowed command"),
    "PREVENT_UNCOMMON_PATH_TYPES": SecurityException("Disallowed access to path type"),
    "PREVENT_ADMIN_OWNED_FILES": SecurityException("Disallowed access to file owned by"),
    "ANY": SecurityException("Any Security exception")
    }

    def _run_test_with_command(self, original_func, expected_result, restrictions, command, shell=False, compare_stderr=False, *args, **kwargs):
        if isinstance(expected_result, SecurityException):
            with pytest.raises(SecurityException) as cm:
                safe_command.run(
                    original_func=original_func,
                    command=command, *args,
                    restrictions=restrictions,
                    shell=shell, **kwargs
                )
            raised_exception = cm.value
            # If the expected exception is not "Any Security exception" then check that the raised exception starts with the expected message
            if expected_result.args[0] != "Any Security exception":
                assert raised_exception.args[0].startswith(expected_result.args[0]) 
            
                
        else:
            result = safe_command.run(
                    original_func=original_func,
                    command=command, *args,
                    restrictions=restrictions,
                    shell=shell, 
                    capture_output=True,
                    text=True,
                    **kwargs,
                    
            )
            if result:
                compare_val = result.stdout.strip() if not compare_stderr else result.stderr.strip()
                assert compare_val == expected_result
                

    def _do_test_command(self, command, expected_result, restrictions, original_func):
        shell = isinstance(command, str)
        self._run_test_with_command(original_func, expected_result, restrictions, command, shell=shell)


    @pytest.mark.parametrize(
        "command",
        [
            "ls -l; whoami",
            "ls -l && whoami",
            "ls -l || whoami",
            "ls -l | whoami",
            "ls -l\nwhoami",
            "ls -l & whoami",
            "echo $(whoami)",
            "echo $(whoami)",
            "echo `whoami`",
            "cat <(whoami)",
            "sh -c 'whoami'",
            "find . -name '*.txt' -exec cat {} + ",
            "find . -name '*.txt' ${BADKEY:--exec} cat {} + ",

            ["ls", "-l;", "whoami"],
            ["ls", "-l", "&&", "whoami"],
            ["ls", "-l", "||", "whoami"],
            ["ls", "-l", "|", "whoami"],
            ["ls", "-l", "\nwhoami"],
            ["ls", "-l", "&", "whoami"],
            ["echo", "$(whoami)"],
            ["echo", "`whoami`"],
            ["cat", "<(whoami)"],
            ["sh", "-c", "'whoami'"],
            ["find", ".", "-name", "'*.txt'", "-exec", "cat", "{}", "+"],
            ["find", ".", "-name", "'*.txt'", "${BADKEY:--exec}", "cat", "{}", "+"],    
        ] 
    )
    def test_check_multiple_commands(self, command, original_func, setup_teardown):
        exception = self.EXCEPTIONS["PREVENT_COMMAND_CHAINING"]
        restrictions = {"PREVENT_COMMAND_CHAINING"}
        self._do_test_command(command, exception, restrictions, original_func)

    @pytest.mark.parametrize(
        "command",
        [
            "cat /etc/shadow",
            "cat /etc/passwd",
            "cat '/etc/passwd'",
            'cat "/etc/passwd"',
            'cat "/etc/pa*sswd"',
            "cat /etc/pa*sswd",
            "cat /etc///pa*sswd*",
            "cat /etc/sudoers",
            "cat ../../../../../../../../../../etc/sudoers.d/../sudoers",
            "cat /etc/sudoers.d/../sudoers",

            ["cat", "/etc/shadow"],
            ["cat", "/etc/passwd"],
            ["cat", "/etc/passwd"],
            ["cat", "/etc/passwd"],
            ["cat", "/etc/pa*sswd"],
            ["cat", "/etc/pa*sswd"],
            ["cat", "/etc///pa*sswd*"],
            ["cat", "/etc/sudoers"],
            ["cat", "../../../../../../../../../../etc/sudoers.d/../sudoers"],
            ["cat", "/etc/sudoers.d/../sudoers"],
        ] 
    )            
    def test_check_sensitive_files(self, command, original_func, setup_teardown):
        exception = self.EXCEPTIONS["PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES"]
        restrictions = {"PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES"}
        self._do_test_command(command, exception, restrictions, original_func)


    @pytest.mark.parametrize(
        "command",
        [
            "ls -l /usr/bin/nc",
            "ls -l /usr/bin/netcat",
            "ls -l /usr/bin/curl",
            "curl https://example.com",
            "sh -c 'curl https://example.com'",
            "sh -c \"curl https://example.com\"",
            "sh -c '  curl https://example.com'",
            "sh -c 'sh -c \" curl https://example.com\" '",
            "sh -c \"sh -c 'curl https://example.com' \"",
            "find . -name '*' -exec curl {} + ",
            "find . -name '*' -exec /usr/bin/curl {} + ",
            "find . -name '*' -exec /usr/bin/cu*l {} + ",
            " netcat -l -p 1234",
            "nc -l -p 1234",            
            "/usr/bin/nc -l -p 1234",
            "/usr/bin/nc* -l -p 1234",
            "/usr/*i**/nc -l -p 1234",
            "{nc,-l,-p,1234}",
            "${BADKEY:-nc} -l -p 1234",
            # Check that IFS can't be used to bypass
            "${IFS}nc${IFS}-l${IFS}-p${IFS}1234",
            "${IFS}/usr/bin/nc*${IFS} -l -p 1234",
            "$IFS            nc${IFS}-l -p 1234",
            "find . -name '*' -exec \"${IFS}/usr/bin/cu*l${IFS}\" {} + ",
            "sh -c 'sh -c \"${IFS}/usr/bin/c*rl${IFS}https://example.com${IFS}\" '",

            ["ls", "-l", "/usr/bin/nc"],
            ["ls", "-l", "/usr/bin/netcat"],
            ["ls", "-l", "/usr/bin/curl"],
            ["curl", "https://example.com"],
            ["sh", "-c", "curl https://example.com"],
            ["sh", "-c", "  curl https://example.com"],
            ["sh", "-c", "sh -c \" curl https://example.com\" "],
            ["sh", "-c", "sh -c 'curl https://example.com' "],
            ["find", ".", "-name", "'*'", "-exec", "curl", "{}", "+"],
            ["find", ".", "-name", "'*'", "-exec", "/usr/bin/curl", "{}", "+"],
            ["find", ".", "-name", "'*'", "-exec", "/usr/bin/cu*l", "{}", "+"],
            [" netcat ", "-l", "-p", "1234"],
            ["nc", "-l", "-p", "1234"],
            ["/usr/bin/nc", "-l", "-p", "1234"],
            ["/usr/bin/nc*", "-l", "-p", "1234"],
            ["/usr/*i**/nc", "-l", "-p", "1234"],
            ["{nc,-l,-p,1234}"],

            ["${IFS}nc${IFS}-l${IFS}-p${IFS}1234"], 
            ["${IFS}/usr/bin/nc*${IFS}", "-l", "-p", "1234"],
            ["$IFS            nc${IFS}", "-p", "1234"],
            ["find", ".", "-name", "'*'", "-exec", "\"${IFS}/usr/bin/cu*l${IFS}\"", "{}", "+"],
            ["sh", "-c", "sh -c \"${IFS}/usr/bin/c*rl${IFS}https://example.com${IFS}\" "],
            
            
        ] 
    ) 
    def test_check_banned_executable(self, command, original_func, setup_teardown):
        exception = self.EXCEPTIONS["PREVENT_COMMON_EXPLOIT_EXECUTABLES"]
        restrictions = {"PREVENT_COMMON_EXPLOIT_EXECUTABLES"}
        self._do_test_command(command, exception, restrictions, original_func)

    @pytest.mark.parametrize(
        "command",
        [
            "cat {fifo_testfile}",
            "cat {symlink_testfile}",
            ["cat", "{fifo_testfile}"],
            ["cat", "{symlink_testfile}"], 
        ] 
    ) 
    def test_check_path_type(self, command, original_func, setup_teardown):
        exception = self.EXCEPTIONS["PREVENT_UNCOMMON_PATH_TYPES"]
        restrictions = {"PREVENT_UNCOMMON_PATH_TYPES"}

        testpaths = setup_teardown
        command = insert_testpaths(command, testpaths)
        self._do_test_command(command, exception, restrictions, original_func)


    @pytest.mark.parametrize(
        "command",
        [
            "cat /etc/passwd",
            "cat /var/log/*",
            "grep -r /var/log",
            ["cat", "/etc/passwd"],
            ["cat", "/var/log/*"],
            ["grep", "-r", "/var/log"],
        ] 
    ) 
    def test_check_file_owner(self, command, original_func, setup_teardown):
        exception = self.EXCEPTIONS["PREVENT_ADMIN_OWNED_FILES"]
        restrictions = {"PREVENT_ADMIN_OWNED_FILES"}
        self._do_test_command(command, exception, restrictions, original_func)
        
  
    @pytest.mark.parametrize(
        "command, expected_result",
        [
            # These commands should not be blocked and should return the expected result
            ("echo HELLO", "HELLO"),
            ("cat {test.txt}", "USERDATA1\nUSERDATA2\nUSERDATA3"),
            ("/bin/cat {test2.txt}", "USERDATA4\nUSERDATA5\nUSERDATA6"),
            # Globbing should not be blocked or affect the result
            ("grep -e 'USERDATA[12]' {test.txt}", "USERDATA1\nUSERDATA2"),
            # Find should not be blocked unless using -exec or trying to find sensitive files
            ("find {rglob_testdir} -name '*.txt' -print -quit", "{rglob_testfile}"),
            
            (["echo", "HELLO"], "HELLO"),
            (["cat", "{test.txt}"], "USERDATA1\nUSERDATA2\nUSERDATA3"),
            (["/bin/cat", "{test2.txt}"], "USERDATA4\nUSERDATA5\nUSERDATA6"),
            (["grep", "-e", "USERDATA[12]", "{test.txt}"], "USERDATA1\nUSERDATA2"),
            (["find", "{rglob_testdir}", "-name", '*.txt', "-print", "-quit"], "{rglob_testfile}"),
        ]
    )
    def test_valid_commands_not_blocked(self, command, expected_result, original_func, setup_teardown):
        if original_func.__name__ == "call":
            # call doesn't have capture_output kwarg so can't compare result and easier to just return than refactor
            return 
        
        testpaths = setup_teardown
        command = insert_testpaths(command, testpaths)
        expected_result = insert_testpaths(expected_result, testpaths)
        
        # Use all restrictions to make sure none of them block the command
        restrictions = [
            "PREVENT_COMMAND_CHAINING", 
            "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES",
            "PREVENT_COMMON_EXPLOIT_EXECUTABLES", 
            "PREVENT_UNCOMMON_PATH_TYPES",
            "PREVENT_ADMIN_OWNED_FILES"
        ]
        self._do_test_command(command, expected_result, restrictions, original_func)


    # FUZZDB tests
    @pytest.mark.parametrize(
        "command",
        [payload.replace('{cmd}', command) for command in [
            "cat /etc/passwd",
            "curl https://example.com",
            "sh -c 'curl https://example.com'",
            "find . -name '*' -exec curl '{}' '+'",
            "nc  -l -p 1234",
        ] for payload in FUZZDB_OS_COMMAND_INJECTION_PAYLOADS]
    )
    def test_fuzzdb_injection_payloads(self, command, original_func):
        restrictions = [
            "PREVENT_COMMAND_CHAINING", 
            "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES",
            "PREVENT_COMMON_EXPLOIT_EXECUTABLES", 
        ]
        self._do_test_command(command, self.EXCEPTIONS["ANY"], restrictions, original_func)
            

    @pytest.mark.parametrize(
        "filepath",
        [payload.replace('{FILE}', file) for file in [
            "/etc/passwd",
            "/etc/passwd*",
            "/etc/pass*d",
            "*etc/pass*d",
            "/et**/pa*sswd",
            
            "etc/passwd",
            "etc/passwd*",
            "etc/pass*d",
            "*etc/pass*d",
            "et**/pa*sswd",
        ] for payload in FUZZDB_PATH_TRAVERSAL_PAYLOADS]
    )
    def test_fuzzdb_traversal_payloads(self, filepath, original_func):        
        restrictions = [
            "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES",
        ]


        try:
            if original_func.__name__ == "run":
                popen_kwargs = {"capture_output": True, "text": True}
            else:
                popen_kwargs = {}

            command = f"cat {filepath}"
            result = safe_command.run(
                    original_func=original_func,
                    command=command,
                    restrictions=restrictions,
                    shell=True, 
                    **popen_kwargs 
            )
            # Anything that is allowed to run is a junk path that does resolve to /etc/passwd
            # and should thus not be blocked by PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES
            if original_func.__name__ == "run":
                assert "root:" not in result.stdout 
            else:
                assert result != 0
        except (SecurityException, OSError) as e:
            if isinstance(e, SecurityException):
                assert e.args[0].startswith("Disallowed access to sensitive file")
            elif isinstance(e, OSError):
                assert e.strerror == "File name too long"
        