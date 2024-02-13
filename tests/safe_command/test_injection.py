import unittest
import subprocess
from pathlib import Path
from os import mkfifo, symlink, get_exec_path, getlogin, chown
from shutil import rmtree, which

from security.safe_command import safe_command
from security.safe_command.api import _parse_command, _resolve_paths_in_parsed_command
from security.exceptions import SecurityException

class TestSafeCommandInjection(unittest.TestCase):
    EXCEPTIONS = {
        "PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES": SecurityException("Disallowed access to sensitive file"),
        "PREVENT_COMMAND_CHAINING": SecurityException("Multiple commands not allowed"),
        "PREVENT_COMMON_EXPLOIT_EXECUTABLES": SecurityException("Disallowed command"),
        "PREVENT_UNCOMMON_PATH_TYPES": SecurityException("Disallowed access to path type"),
        "PREVENT_ADMIN_OWNED_FILES": SecurityException("Disallowed access to file owned by")
    }

    def setUp(self) -> None:
        self.userdata_dir = Path("./userdata/example_user/")
        self.userdata_dir.mkdir(exist_ok=True, parents=True)
        test_data = {
            "testdata.txt": "USERDATA1\nUSERDATA2\nUSERDATA3\n",
            "testdata2.txt": "USERDATA4\nUSERDATA5\nUSERDATA6\n",
            "secret.data": "SECRET-DATA-789\n"
        }

        for filename, data in test_data.items():
            with open(self.userdata_dir / filename, "w") as f:
                f.write(data)
        
        
        self.original_func = subprocess.run
        self.safe_command = new_safe_command
        return super().setUp()

    def tearDown(self) -> None:
        rmtree("./userdata", ignore_errors=True)
        rmtree("./testpaths", ignore_errors=True)
        rmtree("./testpathtypes", ignore_errors=True)
        return super().tearDown()
    
    def _run_test_command(self, expected_result, restrictions, command, shell=False, compare_stderr=False, *args, **kwargs):
        msg = f"\n\nrestrictions: {restrictions}\nshell: {shell}\ncommand: {command}\nexpected_result: {expected_result}"
        if isinstance(expected_result, SecurityException):
            with self.assertRaises(SecurityException, msg=msg) as cm:
                self.safe_command.run(
                    original_func=self.original_func,
                    command=command, *args,
                    restrictions=restrictions,
                    shell=shell, **kwargs
                )
            raised_exception = cm.exception
            self.assertIn(expected_result.args[0], raised_exception.args[0], msg=msg)
                
        else:
            result = self.safe_command.run(
                    original_func=self.original_func,
                    command=command, *args,
                    restrictions=restrictions,
                    shell=shell, **kwargs,
                    capture_output=True,
                    text=True
            )
            if result:
                compare_val = result.stdout.strip() if not compare_stderr else result.stderr.strip()
                self.assertEqual(compare_val, expected_result, msg=msg)


    def _do_test_commands(self, test_commands, restrictions):
        for command, expected_result in test_commands.items():
            if isinstance(command, str):
                shell = True
                self._run_test_command(expected_result, restrictions, command, shell=shell)
            if isinstance(command, tuple):
                command = list(command)
                shell = False
                self._run_test_command(expected_result, restrictions, command, shell=shell)


    def test_parse_command(self):
        for invalid_type in (b"whoami", {"cmd": "value"}, 123, {"cmd", "arg"}):
            with self.assertRaises(TypeError):
                _parse_command(invalid_type) # type: ignore
        for empty in ("", [], [""]):
            self.assertEqual(_parse_command(empty), None)
                
        test_commands = [ 
            # (str_cmd, list_cmd, len_parsed_cmd_list)
            ("whoami", ["whoami"], 1),
            ("ls -l", ["ls", "-l"], 2),
            ("ls -l -a", ["ls", "-l", "-a"], 3),
            ("grep 'test' 'test.txt'", ["grep", "test", "test.txt"], 3),
            ("grep test test.txt", ["grep", "test", "test.txt"], 3),
            ("grep -e 'test test' 'test.txt'", ["grep", "-e", "test test", "test.txt"], 4),
            ("echo 'test1 test2 test3' > test.txt", ["echo", "test1 test2 test3", ">", "test.txt"], 4),
            ('echo "test1 test2 test3" > test.txt', ["echo", "test1 test2 test3", ">", "test.txt"], 4), 
            ("echo test1 test2 test3 > test.txt", ["echo", "test1", "test2", "test3", ">", "test.txt"], 6),
        ]
        for str_cmd, list_cmd, len_parsed_cmd_list in test_commands:
            parsed_str_cmd = _parse_command(str_cmd)
            parsed_list_cmd = _parse_command(list_cmd)
            msg = f"\n\nstr_cmd: {str_cmd}\nlist_cmd: {list_cmd}\nlen_parsed_cmd_list: {len_parsed_cmd_list}"
            msg += f"\nparsed_str_cmd: {parsed_str_cmd}\nparsed_list_cmd: {parsed_list_cmd}"
            self.assertIsInstance(parsed_str_cmd, list, msg=msg)
            self.assertIsInstance(parsed_list_cmd, list, msg=msg)
            self.assertEqual(len(parsed_list_cmd or []), len_parsed_cmd_list, msg=msg)
            self.assertEqual(len(parsed_list_cmd or []), len_parsed_cmd_list, msg=msg)
            self.assertEqual(parsed_str_cmd, parsed_list_cmd, msg=msg)


    def test_resolve_paths_in_parsed_command(self):
        wd = Path.cwd().resolve() / "testpaths"
        wd.mkdir(exist_ok=True)
        (wd / "test.txt").touch()
        (wd / "test2.txt").touch()
        cwd_test = Path("cwdtest.txt").resolve()
        cwd_test.touch()
        fifo_test = (wd / "fifo_test").resolve()
        mkfifo(fifo_test)
        symlink_test = (wd / "symlink_test").resolve()
        symlink(cwd_test, symlink_test) # Target of symlink is cwdtest.txt
        cat, echo, grep, nc, curl, sh = map(lambda cmd: Path(which(cmd) or f"/usr/bin/{cmd}" ), ["cat", "echo", "grep", "nc", "curl", "sh"]) 
        test_commands = {
            # command: expected_paths
            f"echo HELLO": {echo},
            f"cat cwdtest.txt": {cat, cwd_test},
            f"cat ./cwdtest.txt": {cat, cwd_test},
            f"cat cwd*.txt": {cat, cwd_test},
            f"cat {wd}/test.txt": {cat, wd/"test.txt"},
            f"cat '{wd}/test.txt' ": {cat, wd/"test.txt"},
            f'cat "{wd}/test.txt" ': {cat, wd/"test.txt"},
            f"cat {wd}/test.txt {wd}/test2.txt": {cat, wd/"test.txt", wd/"test2.txt"},
            # Check globbing and multiple slashes
            f"cat {wd}/*t.txt {wd}/test?.txt": {cat, wd/"test.txt", wd/"test2.txt"},
            f"cat {wd}///////*t.txt": {cat, wd/"test.txt"},
            f"cat {wd}/../{wd.name}/*.txt": {cat, wd/"test.txt", wd/"test2.txt"},
            # Check globbing in executable path
            f"/bin/c*t '{wd}/test.txt' ": {cat, wd/"test.txt"},
            # Check that /etc or /private/etc for mac handling is correct
            f"cat /etc/passwd /etc/sudoers ": {cat, Path("/etc/passwd").resolve(), Path("/etc/sudoers").resolve()},
            f"/bin/cat /etc/passwd": {cat, Path("/etc/passwd").resolve()},
            # Check fifo and symlink
            f"cat {fifo_test}": {cat, fifo_test},
            # Symlink should resolve to cwdtest.txt so should get the symlink and the target
            f"cat {symlink_test}": {cat, symlink_test, cwd_test}, 
            # Check a command with binary name as an argument
            f"echo 'cat' {wd}/test.txt": {echo, cat, wd/"test.txt"},
            # Command has a directory so should get the dir and all the subfiles and resolved symlink to cwdtest.txt
            f"grep 'cat' -r {wd}": {grep, cat, wd, wd/"test.txt", wd/"test2.txt", fifo_test, cwd_test},
            f"nc -l -p 1234": {nc},
            f"curl https://example.com": {curl},
            f"sh -c 'curl https://example.com'": {sh, curl},
        }
        for command, expected_paths in test_commands.items():
            parsed_command = _parse_command(command)
            abs_paths, abs_path_strings = _resolve_paths_in_parsed_command(parsed_command)
            msg = f"\n\ncommand: {command}\n\nparsed_command: {parsed_command}\n\nexpected_paths: {expected_paths}\n\nabs_paths: {abs_paths}\n\nabs_path_strings: {abs_path_strings}"
            self.assertEqual(abs_paths, expected_paths, msg=msg)
            self.assertEqual(abs_path_strings, {str(p) for p in expected_paths}, msg=msg)


    def test_check_multiple_commands(self):
        exception = self.EXCEPTIONS["PREVENT_COMMAND_CHAINING"]
        restrictions = {"PREVENT_COMMAND_CHAINING"}
        test_commands = {
            # (command, expected_result)
            "echo HELLO": "HELLO",
            ("echo", "HELLO"): "HELLO",
            "ls -l; whoami": exception,
            ("ls", "-l;", "whoami"): exception,
            "ls -l && whoami": exception,
            ("ls", "-l", "&&", "whoami"): exception,
            "ls -l || whoami": exception,
            ("ls", "-l", "||", "whoami"): exception,
            "ls -l | whoami": exception,
            ("ls", "-l", "|", "whoami"): exception,
            "ls -l\nwhoami": exception,
            ("ls", "-l", "\nwhoami"): exception,
            "ls -l & whoami": exception,
            ("ls", "-l", "&", "whoami"): exception,
            "echo $(whoami)": exception,
            ("echo", "$(whoami)"): exception,
            "echo $(whoami)": exception,
            ("echo", "$(whoami)"): exception,
            "echo `whoami`": exception,
            ("echo", "`whoami`"): exception,
            "sh -c 'whoami'": exception,
            ("sh", "-c", "'whoami'"): exception,
            # Find not allowed with -exec but is allowed otherwise
            "find . -name '*.txt' -exec cat {} + ": exception,
            ("find", ".", "-name", "'*.txt'", "-exec", "cat", "{}", "+"): exception,
            f"find {self.userdata_dir} -name testdata.txt -print -quit": "userdata/example_user/testdata.txt",
            ("find", str(self.userdata_dir), "-name", "testdata.txt", "-print", "-quit"): "userdata/example_user/testdata.txt",
            f"grep -e 'USERDATA[12]' {self.userdata_dir}/testdata.txt": "USERDATA1\nUSERDATA2",
            ("grep", "-e", "USERDATA[12]", f"{self.userdata_dir}/testdata.txt"): "USERDATA1\nUSERDATA2",
        }

        self._do_test_commands(test_commands, restrictions)
            
            

    def test_check_sensitive_files(self):
        exception = self.EXCEPTIONS["PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES"]
        restrictions = {"PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES"}
        test_commands = {
            # (command, expected_result)
            f"cat {self.userdata_dir}/testdata.txt": f"USERDATA1\nUSERDATA2\nUSERDATA3",
            ("cat", f"{self.userdata_dir}/testdata.txt"): "USERDATA1\nUSERDATA2\nUSERDATA3",
            f"cat {self.userdata_dir}/testdata2.txt": f"USERDATA4\nUSERDATA5\nUSERDATA6",
            ("cat", f"{self.userdata_dir}/testdata2.txt"): "USERDATA4\nUSERDATA5\nUSERDATA6",
            f"grep 'USERDATA1' {self.userdata_dir}/testdata.txt": "USERDATA1",
            ("grep", "USERDATA1", f"{self.userdata_dir}/testdata.txt"): "USERDATA1",
            f"cat /etc/shadow": exception,
            ("cat", "/etc/shadow"): exception,
            f"cat /etc/passwd": exception,
            ("cat", "/etc/passwd"): exception,
            f"cat '/etc/passwd'": exception,
            ("cat", "/etc/passwd"): exception,
            f'cat "/etc/passwd"': exception,
            ("cat", "/etc/passwd"): exception,
            f'cat "/etc/pa*sswd"': exception,
            ("cat", "/etc/pa*sswd"): exception,
            f"cat /etc/pa*sswd": exception,
            ("cat", "/etc/pa*sswd"): exception,
            f"cat /etc///pa*sswd*": exception,
            ("cat", "/etc///pa*sswd*"): exception,
            f"cat /etc/sudoers": exception,
            ("cat", "/etc/sudoers"): exception,
            f"cat ../../../../../../../../../../etc/sudoers.d/../sudoers": exception,
            ("cat", "../../../../../../../../../../etc/sudoers.d/../sudoers"): exception,
            f"cat /etc/sudoers.d/../sudoers": exception,
            ("cat", "/etc/sudoers.d/../sudoers"): exception,
        }

        self._do_test_commands(test_commands, restrictions)


    def test_check_banned_executable(self):
        exception = self.EXCEPTIONS["PREVENT_COMMON_EXPLOIT_EXECUTABLES"]
        restrictions = {"PREVENT_COMMON_EXPLOIT_EXECUTABLES"}
        test_commands = {
            # (command, expected_result)
            "echo HELLO": "HELLO",
            ("echo", "HELLO"): "HELLO",
            "ls -l /usr/bin/nc": exception,
            ("ls", "-l", "/usr/bin/nc"): exception,
            "ls -l /usr/bin/netcat": exception,
            ("ls", "-l", "/usr/bin/netcat"): exception,
            "ls -l /usr/bin/curl": exception,
            ("ls", "-l", "/usr/bin/curl"): exception,
            "ls -l /usr/bin/wget": exception,
            ("ls", "-l", "/usr/bin/wget"): exception,
            "ls -l /usr/bin/dpkg": exception,
            ("ls", "-l", "/usr/bin/dpkg"): exception,
            "ls -l /usr/bin/rpm": exception,
            ("ls", "-l", "/usr/bin/rpm"): exception,
            "curl https://example.com": exception,
            ("curl", "https://example.com"): exception,
            "sh -c 'curl https://example.com'": exception,
            ("sh", "-c", "curl https://example.com"): exception,
            "find . -name '*' -exec curl {} + ": exception,
            ("find", ".", "-name", "'*'", "-exec", "curl", "{}", "+"): exception,
            "find . -name '*' -exec /usr/bin/curl {} + ": exception,
            ("find", ".", "-name", "'*'", "-exec", "/usr/bin/curl", "{}", "+"): exception,
            "find . -name '*' -exec /usr/bin/cu*l {} + ": exception,
            ("find", ".", "-name", "'*'", "-exec", "/usr/bin/cu*l", "{}", "+"): exception,
            "nc -l -p 1234": exception,
            ("nc", "-l", "-p", "1234"): exception,
            "/bin/nc -l -p 1234": exception,
            ("/bin/nc", "-l", "-p", "1234"): exception,
            "/usr/bin/nc* -l -p 1234": exception,
            ("/usr/bin/nc*", "-l", "-p", "1234"): exception,
            # Check that IFS can't be used to bypass
            "nc$IFS-l${IFS}-p${IFS}1234": exception,
            ("nc$IFS-l${IFS}-p${IFS}1234"): exception,
        }

        self._do_test_commands(test_commands, restrictions)


    def test_check_path_type(self):
        wd = Path.cwd().resolve() / "testpathtypes"
        wd.mkdir(exist_ok=True)
        cwd_test = Path("cwdtest.txt").resolve()
        cwd_test.touch()
        fifo_test = (wd / "fifo_test").resolve()
        mkfifo(fifo_test)
        symlink_test = (wd / "symlink_test").resolve()
        symlink(cwd_test, symlink_test) # Target of symlink is cwdtest.txt

        exception = self.EXCEPTIONS["PREVENT_UNCOMMON_PATH_TYPES"]
        restrictions = {"PREVENT_UNCOMMON_PATH_TYPES"}
        test_commands = {
            # (command, expected_result)
            "echo HELLO": "HELLO",
            ("echo", "HELLO"): "HELLO",
            f"cat {wd}/fifo_test": exception,
            ("cat", f"{wd}/fifo_test"): exception,
            f"cat {wd}/symlink_test": exception,
            ("cat", f"{wd}/symlink_test"): exception,
            f"cat {self.userdata_dir}/testdata.txt": f"USERDATA1\nUSERDATA2\nUSERDATA3",
            ("cat", f"{self.userdata_dir}/testdata.txt"): "USERDATA1\nUSERDATA2\nUSERDATA3",
            f"/bin/cat {self.userdata_dir}/testdata.txt": f"USERDATA1\nUSERDATA2\nUSERDATA3",
            ("/bin/cat", f"{self.userdata_dir}/testdata.txt"): "USERDATA1\nUSERDATA2\nUSERDATA3",
        }

        self._do_test_commands(test_commands, restrictions)
        

    def test_check_file_owner(self):
        exception = self.EXCEPTIONS["PREVENT_ADMIN_OWNED_FILES"]
        restrictions = {"PREVENT_ADMIN_OWNED_FILES"}

        test_commands = {
            # (command, expected_result)
            "echo HELLO": "HELLO",
            ("echo", "HELLO"): "HELLO",
            f"cat {self.userdata_dir}/testdata.txt": f"USERDATA1\nUSERDATA2\nUSERDATA3",
            ("cat", f"{self.userdata_dir}/testdata.txt"): "USERDATA1\nUSERDATA2\nUSERDATA3",
            f"cat /etc/passwd": exception,
            ("cat", "/etc/passwd"): exception,
            f"cat /var/log/*": exception,
            ("cat", "/var/log/*"): exception,
        }

        self._do_test_commands(test_commands, restrictions)


if __name__ == "__main__":
    unittest.main()