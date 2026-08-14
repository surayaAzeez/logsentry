"""Parser for Windows Security event logs exported to CSV.

This is the shape you get from ``Get-WinEvent ... | Export-Csv`` or most SIEM
exports. Required columns: ``TimeCreated``, ``EventID``. Optional: ``Computer``,
``TargetUserName``, ``IpAddress``, ``IpPort``, ``LogonType``.

Event IDs mapped:

======  ==========================================
4624    Successful logon
4625    Failed logon
4634    Logoff
4672    Special privileges assigned (admin logon)
4720    User account created
======  ==========================================
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from ..models import EventType, LogEvent
from .base import Parser, register

_EVENT_ID_MAP = {
    "4624": EventType.AUTH_SUCCESS,
    "4625": EventType.AUTH_FAILURE,
    "4634": EventType.SESSION_CLOSED,
    "4672": EventType.PRIVILEGE_ESCALATION,
    "4720": EventType.OTHER,
}

_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%d/%m/%Y %H:%M:%S",
)


def _parse_time(value: str) -> datetime | None:
    value = value.strip().split(".")[0].replace("Z", "")
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


@register
class WindowsSecurityCSVParser(Parser):
    """Normalises exported Windows Security events."""

    name = "winsec"

    def __init__(self, default_year: int | None = None) -> None:
        super().__init__(default_year)
        self._header: list[str] | None = None

    def parse_line(self, line: str) -> LogEvent | None:
        """Parse a single CSV row.

        The first row containing ``EventID`` is treated as the header and
        remembered, which is what makes line-at-a-time parsing (and therefore
        :meth:`sniff`) work on this format.
        """
        line = line.strip()
        if not line:
            return None

        row = next(csv.reader(io.StringIO(line)), None)
        if not row:
            return None

        if self._header is None:
            if any(cell.strip().lstrip("﻿") == "EventID" for cell in row):
                self._header = [c.strip().lstrip("﻿") for c in row]
            return None

        if len(row) != len(self._header):
            return None

        # strict=True is safe: the length check above guarantees they match.
        record = dict(zip(self._header, (c.strip() for c in row), strict=True))
        event_id = record.get("EventID", "")
        event_type = _EVENT_ID_MAP.get(event_id)
        if event_type is None:
            return None

        timestamp = _parse_time(record.get("TimeCreated", ""))
        if timestamp is None:
            return None

        ip = record.get("IpAddress") or None
        if ip in ("-", "::1", ""):
            ip = None
        port = record.get("IpPort") or ""
        user = record.get("TargetUserName") or None
        if user in ("-", ""):
            user = None

        return LogEvent(
            timestamp=timestamp,
            source=self.name,
            event_type=event_type,
            raw=line,
            host=record.get("Computer") or None,
            user=user,
            src_ip=ip,
            src_port=int(port) if port.isdigit() else None,
            metadata={
                "event_id": event_id,
                "logon_type": record.get("LogonType"),
            },
        )

    def parse_file(self, path: str | Path) -> Iterator[LogEvent]:
        # Header state is per-file; reset so a second file re-learns its columns.
        self._header = None
        yield from super().parse_file(path)
