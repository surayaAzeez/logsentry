"""Parser for the nginx/Apache "combined" access log format.

Sample line::

    45.83.12.9 - - [11/Mar/2025:03:14:07 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "sqlmap/1.7"
"""

from __future__ import annotations

import re
from datetime import datetime

from ..models import EventType, LogEvent
from .base import Parser, register

_COMBINED_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>\S+))?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


@register
class NginxAccessParser(Parser):
    """Normalises HTTP access logs so web-recon rules can run over them."""

    name = "nginx"

    def parse_line(self, line: str) -> LogEvent | None:
        match = _COMBINED_RE.match(line.strip())
        if not match:
            return None

        try:
            timestamp = datetime.strptime(match.group("time"), _TIME_FMT)
        except ValueError:
            return None
        # Detections compare timestamps across sources; normalising to naive UTC
        # avoids mixing aware and naive datetimes downstream.
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(tz=None).replace(tzinfo=None)

        user = match.group("user")
        size = match.group("size")

        return LogEvent(
            timestamp=timestamp,
            source=self.name,
            event_type=EventType.HTTP_REQUEST,
            raw=line.strip(),
            user=None if user == "-" else user,
            src_ip=match.group("ip"),
            metadata={
                "method": match.group("method"),
                "path": match.group("path"),
                "status": int(match.group("status")),
                "size": 0 if size == "-" else int(size),
                "referer": match.group("referer"),
                "user_agent": match.group("agent") or "",
            },
        )
