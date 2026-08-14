"""Core data structures shared by parsers, detections and reporting.

Everything downstream speaks in terms of :class:`LogEvent` (one normalised line
of a log file) and :class:`Finding` (one thing a detection rule flagged).
Keeping this contract narrow is what lets a new parser or a new rule drop in
without touching anything else.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    """``plural(1, 'event') -> '1 event'``; ``plural(3, 'event') -> '3 events'``."""
    word = singular if count == 1 else (plural_form or f"{singular}s")
    return f"{count:,} {word}"


class Severity(str, Enum):
    """Ordered severity levels. Inherits ``str`` so it serialises to JSON cleanly."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self)

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class EventType(str, Enum):
    """Normalised event vocabulary.

    Parsers translate source-specific wording ("Failed password", "Event ID
    4625", "HTTP 401") into these, so detections never need to know which
    product produced a line.
    """

    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_INVALID_USER = "auth_invalid_user"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    HTTP_REQUEST = "http_request"
    OTHER = "other"


@dataclass
class LogEvent:
    """One normalised log line."""

    timestamp: datetime
    source: str
    event_type: EventType
    raw: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_failure(self) -> bool:
        return self.event_type in (
            EventType.AUTH_FAILURE,
            EventType.AUTH_INVALID_USER,
        )

    @property
    def is_external(self) -> bool:
        """True when ``src_ip`` is a routable public address."""
        if not self.src_ip:
            return False
        try:
            ip = ipaddress.ip_address(self.src_ip)
        except ValueError:
            return False
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type.value,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "metadata": self.metadata,
        }


@dataclass
class Finding:
    """One detection hit, ready to be reported to an analyst."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    first_seen: datetime
    last_seen: datetime
    src_ip: str | None = None
    users: list[str] = field(default_factory=list)
    event_count: int = 0
    mitre: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""

    MAX_EVIDENCE = 5

    def __post_init__(self) -> None:
        # Reports get unreadable if a rule dumps 4,000 raw lines into one card.
        self.evidence = self.evidence[: self.MAX_EVIDENCE]

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "src_ip": self.src_ip,
            "users": self.users,
            "event_count": self.event_count,
            "mitre": self.mitre,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
