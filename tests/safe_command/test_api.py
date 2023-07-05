import pytest
import subprocess
from security.exceptions import SecurityException
from security import safe_command


@pytest.mark.parametrize("original_func", [subprocess.run, subprocess.call])
class TestSafeCommandApi:
    def _assert_equal_result(self, original_func, expected_result, safe_api_result):
        assert type(expected_result) == type(safe_api_result)
        if original_func.__name__ == "call":
            assert expected_result == safe_api_result
        else:
            assert expected_result.returncode == safe_api_result.returncode

    def test_api_returns_same_result_lst_command(self, original_func):
        command = ["echo", "hello"]
        expected_result = original_func(command)
        safe_api_result = safe_command.run(original_func, command)
        self._assert_equal_result(original_func, expected_result, safe_api_result)

    def test_api_returns_same_result_str_command_shell(self, original_func):
        command = "echo hello"
        expected_result = original_func(command, shell=True)
        safe_api_result = safe_command.run(original_func, command, shell=True)
        self._assert_equal_result(original_func, expected_result, safe_api_result)

    @pytest.mark.parametrize("command", ["", []])
    def test_empty_command_runs(self, command, original_func):
        with pytest.raises((PermissionError, IndexError)):
            safe_command.run(original_func, command)

    @pytest.mark.parametrize(
        "command",
        [
            "cat ///etc//passwd",
            "cat /etc/passwd",
            "cat ../../../../../../../../../../../../../../../../../../../../../../../../../../..//etc/passwd",
            "ls /etc/shadow",
            "touch /etc/group",
            "tee /etc/gshadow",
        ],
    )
    def test_blocks_sensitive_files(self, command, original_func):
        with pytest.raises(SecurityException):
            safe_command.run(original_func, command)
