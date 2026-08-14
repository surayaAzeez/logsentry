"""Shared fixtures and helpers for the test suite."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from logsentry.models import EventType, LogEvent

BASE = datetime(2025, 3, 11, 3, 0, 0)


def make_event(
    offset_seconds: int = 0,
    event_type: EventType = EventType.AUTH_FAILURE,
    user: str = "root",
    src_ip: str = "45.83.12.9",
    raw: str = "",
    **metadata: object,
) -> LogEvent:
    """Build a LogEvent without needing a real log line."""
    return LogEvent(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source="test",
        event_type=event_type,
        raw=raw or f"synthetic {event_type.value} {user}@{src_ip}",
        host="web-01",
        user=user,
        src_ip=src_ip,
        metadata=dict(metadata),
    )


@pytest.fixture
def sample_auth_log(tmp_path):
    """A small auth.log containing one clear brute-force burst."""
    lines = [
        "Mar 11 03:14:07 web-01 sshd[24601]: Failed password for root from 45.83.12.9 port 51234 ssh2",
        "Mar 11 03:14:09 web-01 sshd[24602]: Invalid user admin from 45.83.12.9 port 51236",
        "Mar 11 03:14:11 web-01 sshd[24603]: Failed password for invalid user admin from 45.83.12.9 port 51236 ssh2",
        "Mar 11 09:20:41 web-01 sshd[24730]: Accepted publickey for deploy from 10.0.4.7 port 42011 ssh2",
        "Mar 11 09:21:02 web-01 sudo: deploy : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "Mar 11 09:22:00 web-01 CRON[999]: pam_unix(cron:session): session closed for user root",
    ]
    path = tmp_path / "auth.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def sample_access_log(tmp_path):
    """A small nginx access log with benign and scanner traffic."""
    lines = [
        '129.10.1.5 - - [11/Mar/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0"',
        '196.52.43.87 - - [11/Mar/2025:02:41:00 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "sqlmap/1.7.11"',
        '196.52.43.87 - - [11/Mar/2025:02:41:03 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "sqlmap/1.7.11"',
        '89.248.165.72 - - [11/Mar/2025:05:12:00 +0000] "GET /.env HTTP/1.1" 200 1834 "-" "Go-http-client/2.0"',
        '89.248.165.72 - - [11/Mar/2025:05:12:11 +0000] "GET /.git/config HTTP/1.1" 200 412 "-" "Go-http-client/2.0"',
        '89.248.165.72 - - [11/Mar/2025:05:12:22 +0000] "GET /api/../../etc/passwd HTTP/1.1" 400 162 "-" "Go-http-client/2.0"',
    ]
    path = tmp_path / "access.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
