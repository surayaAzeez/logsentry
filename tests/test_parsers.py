"""Parser tests: correct fields out, and junk in doesn't crash anything."""

from __future__ import annotations

import pytest

from logsentry.models import EventType
from logsentry.parsers import (
    NginxAccessParser,
    SSHDParser,
    WindowsSecurityCSVParser,
    detect_parser,
)


class TestSSHDParser:
    def test_failed_password(self):
        line = (
            "Mar 11 03:14:07 web-01 sshd[24601]: Failed password for root "
            "from 45.83.12.9 port 51234 ssh2"
        )
        event = SSHDParser(default_year=2025).parse_line(line)

        assert event is not None
        assert event.event_type is EventType.AUTH_FAILURE
        assert event.user == "root"
        assert event.src_ip == "45.83.12.9"
        assert event.src_port == 51234
        assert event.host == "web-01"
        assert event.timestamp.year == 2025
        assert event.timestamp.month == 3
        assert event.is_failure

    def test_invalid_user_takes_priority_over_failed_password(self):
        """'Failed password for invalid user X' must not be read as a known user."""
        line = (
            "Mar 11 03:14:11 web-01 sshd[24603]: Failed password for invalid user "
            "admin from 45.83.12.9 port 51236 ssh2"
        )
        event = SSHDParser(default_year=2025).parse_line(line)

        assert event is not None
        assert event.event_type is EventType.AUTH_INVALID_USER
        assert event.user == "admin"

    def test_accepted_login(self):
        line = (
            "Mar 11 09:20:41 web-01 sshd[24730]: Accepted publickey for deploy "
            "from 10.0.4.7 port 42011 ssh2"
        )
        event = SSHDParser(default_year=2025).parse_line(line)

        assert event is not None
        assert event.event_type is EventType.AUTH_SUCCESS
        assert event.user == "deploy"
        assert event.metadata["auth_method"] == "publickey"
        assert not event.is_external  # 10.0.0.0/8 is private

    def test_sudo_command(self):
        line = (
            "Mar 11 09:21:02 web-01 sudo: deploy : TTY=pts/0 ; PWD=/srv ; "
            "USER=root ; COMMAND=/bin/cat /etc/shadow"
        )
        event = SSHDParser(default_year=2025).parse_line(line)

        assert event is not None
        assert event.event_type is EventType.PRIVILEGE_ESCALATION
        assert event.user == "deploy"
        assert event.metadata["target_user"] == "root"
        assert event.metadata["command"] == "/bin/cat /etc/shadow"

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "   ",
            "not a log line at all",
            "Mar 11 03:14:07 web-01 sshd[24601]: Received disconnect from 1.2.3.4",
            "Xyz 99 99:99:99 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ],
    )
    def test_malformed_lines_return_none(self, line):
        assert SSHDParser(default_year=2025).parse_line(line) is None

    def test_parse_file_counts_skipped_lines(self, sample_auth_log):
        parser = SSHDParser(default_year=2025)
        events = list(parser.parse_file(sample_auth_log))

        assert len(events) == 5  # the CRON line is not an sshd/sudo event
        assert parser.skipped == 1


class TestNginxParser:
    def test_combined_format(self):
        line = (
            '45.83.12.9 - - [11/Mar/2025:03:14:07 +0000] "GET /wp-login.php HTTP/1.1" '
            '404 162 "-" "sqlmap/1.7"'
        )
        event = NginxAccessParser().parse_line(line)

        assert event is not None
        assert event.event_type is EventType.HTTP_REQUEST
        assert event.src_ip == "45.83.12.9"
        assert event.metadata["status"] == 404
        assert event.metadata["path"] == "/wp-login.php"
        assert event.metadata["user_agent"] == "sqlmap/1.7"
        assert event.timestamp.tzinfo is None  # normalised to naive

    def test_dash_size_becomes_zero(self):
        line = '1.2.3.4 - - [11/Mar/2025:03:14:07 +0000] "GET / HTTP/1.1" 304 -'
        event = NginxAccessParser().parse_line(line)

        assert event is not None
        assert event.metadata["size"] == 0

    def test_rejects_non_http_lines(self):
        assert NginxAccessParser().parse_line("Mar 11 03:14:07 web-01 sshd[1]: hi") is None


class TestWindowsParser:
    def test_csv_with_header(self, tmp_path):
        csv_text = (
            "TimeCreated,EventID,Computer,TargetUserName,IpAddress,IpPort,LogonType\n"
            "2025-03-11 03:14:07,4625,DC-01,administrator,45.83.12.9,51234,3\n"
            "2025-03-11 03:15:00,4624,DC-01,j.okoro,10.0.4.7,49152,2\n"
            "2025-03-11 03:16:00,9999,DC-01,noise,10.0.4.7,49152,2\n"
        )
        path = tmp_path / "security.csv"
        path.write_text(csv_text, encoding="utf-8")

        events = list(WindowsSecurityCSVParser().parse_file(path))

        assert len(events) == 2  # unmapped event ID 9999 is dropped
        assert events[0].event_type is EventType.AUTH_FAILURE
        assert events[0].user == "administrator"
        assert events[1].event_type is EventType.AUTH_SUCCESS

    def test_header_state_resets_between_files(self, tmp_path):
        header = "TimeCreated,EventID,TargetUserName,IpAddress\n"
        first = tmp_path / "a.csv"
        second = tmp_path / "b.csv"
        first.write_text(header + "2025-03-11 03:14:07,4625,bob,1.2.3.4\n", encoding="utf-8")
        second.write_text(header + "2025-03-11 04:14:07,4625,eve,5.6.7.8\n", encoding="utf-8")

        parser = WindowsSecurityCSVParser()
        assert len(list(parser.parse_file(first))) == 1
        assert len(list(parser.parse_file(second))) == 1


class TestAutoDetection:
    def test_detects_sshd(self, sample_auth_log):
        assert isinstance(detect_parser(sample_auth_log), SSHDParser)

    def test_detects_nginx(self, sample_access_log):
        assert isinstance(detect_parser(sample_access_log), NginxAccessParser)

    def test_detects_windows_csv(self, tmp_path):
        path = tmp_path / "sec.csv"
        path.write_text(
            "TimeCreated,EventID,TargetUserName,IpAddress\n"
            "2025-03-11 03:14:07,4625,administrator,45.83.12.9\n",
            encoding="utf-8",
        )
        assert isinstance(detect_parser(path), WindowsSecurityCSVParser)

    def test_gzip_files_are_read(self, tmp_path):
        import gzip

        path = tmp_path / "auth.log.gz"
        line = (
            "Mar 11 03:14:07 web-01 sshd[24601]: Failed password for root "
            "from 45.83.12.9 port 51234 ssh2\n"
        )
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(line)

        events = list(SSHDParser(default_year=2025).parse_file(path))
        assert len(events) == 1
