"""Detection rule plumbing.

A rule takes the full list of :class:`~logsentry.models.LogEvent` objects and
returns :class:`~logsentry.models.Finding` objects. Rules are registered by
decorating them with :func:`register_rule`, so adding a file under
``detections/`` and importing it in ``__init__`` is all it takes to ship a new
detection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from ..models import Finding, LogEvent

RULES: list[type[Rule]] = []


def register_rule(cls: type[Rule]) -> type[Rule]:
    RULES.append(cls)
    return cls


class Rule(ABC):
    """Base class for detection rules."""

    rule_id: str = "RULE-0000"
    title: str = "Unnamed rule"
    mitre: list[str] = []
    #: Per-rule tunables, overridable from a YAML/JSON config or the CLI.
    defaults: dict[str, Any] = {}

    def __init__(self, **options: Any) -> None:
        config = dict(self.defaults)
        # Ignore unknown keys so one shared config blob can feed every rule.
        config.update({k: v for k, v in options.items() if k in self.defaults})
        self.config = config

    def __getattr__(self, item: str) -> Any:
        # Lets rules read tunables as ``self.threshold`` instead of
        # ``self.config["threshold"]``. Only consulted for missing attributes.
        try:
            return self.__dict__["config"][item]
        except KeyError as exc:
            raise AttributeError(item) from exc

    @abstractmethod
    def run(self, events: Sequence[LogEvent]) -> list[Finding]:
        """Analyse events and return findings."""


def sliding_window(
    events: Sequence[LogEvent], window: timedelta, threshold: int
) -> list[list[LogEvent]]:
    """Return maximal event bursts of >= ``threshold`` within ``window``.

    Events must already be sorted by timestamp. Uses the standard two-pointer
    sweep: advance ``end``, drag ``start`` forward until the span fits the
    window, and record the burst once it is large enough. Overlapping bursts are
    merged so one attack produces one finding rather than one per event.
    """
    if threshold <= 0 or not events:
        return []

    bursts: list[list[LogEvent]] = []
    start = 0
    current: list[LogEvent] | None = None

    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        span = list(events[start : end + 1])
        if len(span) >= threshold:
            if current is not None and span[0].timestamp <= current[-1].timestamp:
                # Same burst still growing - extend rather than emit a new one.
                seen = {id(e) for e in current}
                current.extend(e for e in span if id(e) not in seen)
            else:
                current = span
                bursts.append(current)

    return bursts
