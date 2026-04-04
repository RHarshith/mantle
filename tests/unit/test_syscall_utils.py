"""Unit tests for mantle.dashboard.syscall_utils."""

import pytest

from mantle.analysis.syscall_parser import (
    command_network_targets,
    extract_fd,
    extract_quoted,
    is_noisy_path,
    is_user_visible_path,
    parse_open_mode,
    parse_ret_status,
    parse_socket_address,
    socket_family,
    socket_transport,
)

NOISY_PREFIXES = ("/usr/lib/", "/lib/", "/proc/", "/sys/", "/etc/ld.so")
NOISY_SUFFIXES = (".pyc", ".so", "__pycache__")
SYSTEM_PREFIXES = ("/usr/", "/lib/", "/etc/", "/proc/", "/sys/", "/dev/", "/run/", "/var/lib/", "/var/cache/")


@pytest.mark.unit
class TestExtractQuoted:
    def test_single_quoted_string(self):
        assert extract_quoted('openat(AT_FDCWD, "/etc/passwd", O_RDONLY)') == ["/etc/passwd"]

    def test_multiple_quoted_strings(self):
        result = extract_quoted('rename("/tmp/old", "/tmp/new")')
        assert result == ["/tmp/old", "/tmp/new"]

    def test_no_quotes(self):
        assert extract_quoted("read(3, 0x7fff, 1024)") == []

    def test_escaped_quotes(self):
        result = extract_quoted(r'"hello\"world"')
        assert len(result) >= 1

    def test_empty_string(self):
        assert extract_quoted("") == []


@pytest.mark.unit
class TestIsNoisyPath:
    def test_system_lib(self):
        assert is_noisy_path("/usr/lib/libm.so", NOISY_PREFIXES, NOISY_SUFFIXES)

    def test_proc(self):
        assert is_noisy_path("/proc/self/status", NOISY_PREFIXES, NOISY_SUFFIXES)

    def test_pyc_file(self):
        assert is_noisy_path("/home/user/project/__pycache__/mod.pyc", NOISY_PREFIXES, NOISY_SUFFIXES)

    def test_user_file_not_noisy(self):
        assert not is_noisy_path("/home/user/project/main.py", NOISY_PREFIXES, NOISY_SUFFIXES)

    def test_site_packages_without_mantle(self):
        assert is_noisy_path("/home/user/.venv/lib/python3.11/site-packages/requests/api.py", NOISY_PREFIXES, NOISY_SUFFIXES)

    def test_site_packages_with_mantle(self):
        assert not is_noisy_path("/home/user/.venv/lib/python3.11/site-packages/mantle/store.py", NOISY_PREFIXES, NOISY_SUFFIXES)


@pytest.mark.unit
class TestIsUserVisiblePath:
    def test_home_path(self):
        assert is_user_visible_path("/home/user/project/file.py", SYSTEM_PREFIXES)

    def test_system_path(self):
        assert not is_user_visible_path("/usr/bin/python3", SYSTEM_PREFIXES)

    def test_socket_pseudo_path(self):
        assert not is_user_visible_path("socket:[12345]", SYSTEM_PREFIXES)

    def test_pipe_pseudo_path(self):
        assert not is_user_visible_path("pipe:[67890]", SYSTEM_PREFIXES)

    def test_empty(self):
        assert not is_user_visible_path("", SYSTEM_PREFIXES)

    def test_tmp_path(self):
        assert is_user_visible_path("/tmp/agent_output.txt", SYSTEM_PREFIXES)

    def test_venv_path(self):
        assert not is_user_visible_path("/home/user/.venv/lib/python3.11/site-packages/foo.py", SYSTEM_PREFIXES)


@pytest.mark.unit
class TestParseOpenMode:
    def test_readonly(self):
        assert parse_open_mode("O_RDONLY") == "file_read"

    def test_wronly(self):
        assert parse_open_mode("O_WRONLY|O_CREAT|O_TRUNC") == "file_write"

    def test_rdwr(self):
        assert parse_open_mode("O_RDWR") == "file_write"

    def test_creat(self):
        assert parse_open_mode("O_CREAT") == "file_write"


@pytest.mark.unit
class TestExtractFd:
    def test_valid_fd(self):
        assert extract_fd("3, 0x7fff, 1024") == 3

    def test_zero_fd(self):
        assert extract_fd("0, buf, 256") == 0

    def test_no_fd(self):
        assert extract_fd("invalid") == -1

    def test_large_fd(self):
        assert extract_fd("255, data") == 255


@pytest.mark.unit
class TestSocketFamily:
    def test_ipv4(self):
        assert socket_family("AF_INET, SOCK_STREAM") == "AF_INET"

    def test_ipv6(self):
        assert socket_family("AF_INET6, SOCK_STREAM") == "AF_INET6"

    def test_unix(self):
        assert socket_family("AF_UNIX, SOCK_STREAM") == "AF_UNIX"

    def test_unknown(self):
        assert socket_family("AF_NETLINK") == "other"


@pytest.mark.unit
class TestSocketTransport:
    def test_tcp(self):
        assert socket_transport("SOCK_STREAM") == "tcp"

    def test_udp(self):
        assert socket_transport("SOCK_DGRAM") == "udp"

    def test_unknown(self):
        assert socket_transport("SOCK_RAW") == "other"


@pytest.mark.unit
class TestParseSocketAddress:
    def test_ipv4_address(self):
        result = parse_socket_address('sin_addr=inet_addr("10.0.0.1"), sin_port=htons(443)')
        assert result["host"] == "10.0.0.1"
        assert result["port"] == "443"
        assert result["endpoint"] == "10.0.0.1:443"

    def test_unix_socket(self):
        result = parse_socket_address('sun_path="/var/run/docker.sock"')
        assert result["host"] == "unix"
        assert result["endpoint"] == "unix:/var/run/docker.sock"

    def test_unknown_format(self):
        result = parse_socket_address("garbage")
        assert result["host"] == "unknown"


@pytest.mark.unit
class TestParseRetStatus:
    def test_success(self):
        result = parse_ret_status("0")
        assert result["ok"]
        assert result["value"] == 0

    def test_success_with_bytes(self):
        result = parse_ret_status("1024")
        assert result["ok"]
        assert result["value"] == 1024

    def test_error(self):
        result = parse_ret_status("-1 ENOENT (No such file or directory)")
        assert not result["ok"]
        assert result["error"] == "ENOENT"


@pytest.mark.unit
class TestCommandNetworkTargets:
    def test_https_url(self):
        targets = command_network_targets("curl https://api.openai.com/v1/models")
        assert "api.openai.com:443" in targets

    def test_http_url_with_explicit_port(self):
        targets = command_network_targets("curl http://localhost:8080/api")
        assert "localhost:8080" in targets

    def test_http_url_default_port(self):
        targets = command_network_targets("curl http://example.com/api")
        assert "example.com:80" in targets

    def test_git_ssh(self):
        targets = command_network_targets("git clone git@github.com:user/repo.git")
        assert "github.com:22" in targets

    def test_no_targets(self):
        assert command_network_targets("ls -la") == []

    def test_empty(self):
        assert command_network_targets("") == []

    def test_deduplication(self):
        targets = command_network_targets("curl https://api.openai.com/a https://api.openai.com/b")
        assert targets.count("api.openai.com:443") == 1
