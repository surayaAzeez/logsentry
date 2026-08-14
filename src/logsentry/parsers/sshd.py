"""Parser for OpenSSH messages in a syslog-formatted ``auth.log``.

Sample lines this handles::

    Mar 11 03:14:07 web-01 sshd[24601]: Failed password for root from 45.83.12.9 port 51234 ssh2
    Mar 11 03:14:09 web-01 sshd[24601]: Invalid user admin from 45.83.12.9 port 51236
    Mar 11 03:20:41 web-01 sshd[24730]: Accepted publickey for deploy from 10.0.4.7 port 42011 ssh2
    Mar 11 03:21:02 web-01 sudo: deploy : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/bash
"""

from __future__ import annotations

import re
from datetime import datetime

from ..models import EventType, LogEvent
from .base import Parser, register

# "Mar 11 03:14:07 web-01 sshd[24601]: <message>"
_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Ordered most-specific first: "Failed password for invalid user bob" must match
# the invalid-user rule before the generic failed-password rule sees it.
_MESSAGE_PATTERNS: list[tuple[re.Pattern[str], EventType]] = [
    (
        re.compile(
            r"^Failed (?P<method>\w+) for invalid user (?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        EventType.AUTH_INVALID_USER,
    ),
    (
        re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
        EventType.AUTH_INVALID_USER,
    ),
    (
        re.compile(
            r"^Failed (?P<method>\w+) for (?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        EventType.AUTH_FAILURE,
    ),
    (
        re.compile(
            r"^Accepted (?P<method>\S+) for (?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        EventType.AUTH_SUCCESS,
    ),
    (
        re.compile(r"^Connection closed by (?:authenticating user \S+ )?(?P<ip>\S+)"),
        EventType.SESSION_CLOSED,
    ),
    (
        re.compile(r"^pam_unix\(\S+\): session opened for user (?P<user>\S+)"),
        EventType.SESSION_OPENED,
    ),
]

# sudo lines look nothing like sshd lines, so they get their own pattern.
_SUDO_RE = re.compile(
    r"^(?P<user>\S+)\s*:\s*(?P<flags>.*?)USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
)


@register
class SSHDParser(Parser):
    """Normalises OpenSSH and sudo authentication events."""

    name = "sshd"

    def parse_line(self, line: str) -> LogEvent | None:
        match = _SYSLOG_RE.match(line.strip())
        if not match:
            return None

        timestamp = self._build_timestamp(
            match.group("month"), match.group("day"), match.group("time")
        )
        if timestamp is None:
            return None

        host = match.group("host")
        proc = match.group("proc")
        message = match.group("message")

        if proc.startswith("sudo"):
            return self._parse_sudo(line, timestamp, host, message)
        if not proc.startswith("sshd"):
            return None

        for pattern, event_type in _MESSAGE_PATTERNS:
            m = pattern.match(message)
            if not m:
                continue
            groups = m.groupdict()
            port = groups.get("port")
            return LogEvent(
                timestamp=timestamp,
                source=self.name,
                event_type=event_type,
                raw=line.strip(),
                host=host,
                user=groups.get("user"),
                src_ip=groups.get("ip"),
                src_port=int(port) if port else None,
                metadata={
                    "process": proc,
                    "pid": match.group("pid"),
                    "auth_method": groups.get("method"),
                },
            )
        return None

    def _parse_sudo(
        self, line: str, timestamp: datetime, host: str, message: str
    ) -> LogEvent | None:
        m = _SUDO_RE.match(message)
        if not m:
            return None
        return LogEvent(
            timestamp=timestamp,
            source=self.name,
            event_type=EventType.PRIVILEGE_ESCALATION,
            raw=line.strip(),
            host=host,
            user=m.group("user"),
            metadata={
                "process": "sudo",
                "target_user": m.group("target"),
                "command": m.group("command").strip(),
            },
        )

    def _build_timestamp(self, month: str, day: str, time_str: str) -> datetime | None:
        month_num = _MONTHS.get(month)
        if month_num is None:
            return None
        try:
            hour, minute, second = (int(p) for p in time_str.split(":"))
            return datetime(
                self.default_year, month_num, int(day), hour, minute, second
            )
        except ValueError:
            # Guards against Feb 30 in a corrupted line, among other things.
            return None
