"""The analysis engine: parse files, run every rule, collect findings."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .detections import RULES, Rule
from .models import Finding, LogEvent, Severity
from .parsers import PARSERS, detect_parser


@dataclass
class AnalysisResult:
    """Everything one run produced, ready to hand to a reporter."""

    findings: list[Finding] = field(default_factory=list)
    events: list[LogEvent] = field(default_factory=list)
    files_analyzed: list[str] = field(default_factory=list)
    parse_errors: int = 0
    started_at: datetime = field(default_factory=datetime.now)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def unique_attacker_ips(self) -> list[str]:
        return sorted({f.src_ip for f in self.findings if f.src_ip})

    @property
    def time_range(self) -> tuple[datetime, datetime] | None:
        if not self.events:
            return None
        stamps = [e.timestamp for e in self.events]
        return min(stamps), max(stamps)

    def to_dict(self) -> dict[str, Any]:
        span = self.time_range
        return {
            "generated_at": self.started_at.isoformat(),
            "files_analyzed": self.files_analyzed,
            "events_parsed": self.event_count,
            "lines_skipped": self.parse_errors,
            "log_time_range": {
                "start": span[0].isoformat() if span else None,
                "end": span[1].isoformat() if span else None,
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.severity_counts,
                "unique_source_ips": self.unique_attacker_ips,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class Engine:
    """Runs the configured rule set over one or more log files."""

    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        rule_options: dict[str, Any] | None = None,
        min_severity: Severity = Severity.INFO,
    ) -> None:
        options = rule_options or {}
        # Instantiating from RULES (rather than taking classes) means callers can
        # inject a single hand-configured rule in tests.
        self.rules = list(rules) if rules is not None else [cls(**options) for cls in RULES]
        self.min_severity = min_severity

    def analyze_files(
        self, paths: Iterable[str | Path], fmt: str | None = None, year: int | None = None
    ) -> AnalysisResult:
        result = AnalysisResult()

        for path in paths:
            path = Path(path)
            if not path.exists():
                raise FileNotFoundError(f"Log file not found: {path}")
            parser = PARSERS[fmt](default_year=year) if fmt else detect_parser(path, year)
            events = list(parser.parse_file(path))
            result.events.extend(events)
            result.parse_errors += parser.skipped
            result.files_analyzed.append(str(path))

        return self.analyze_events(result.events, result)

    def analyze_events(
        self, events: Sequence[LogEvent], result: AnalysisResult | None = None
    ) -> AnalysisResult:
        result = result or AnalysisResult(events=list(events))
        # Rules assume chronological order; sort once here instead of in each rule.
        ordered = sorted(events, key=lambda e: e.timestamp)

        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.run(ordered))

        findings = [f for f in findings if f.severity.rank >= self.min_severity.rank]
        # Most severe first, then most recent - the order an analyst triages in.
        findings.sort(key=lambda f: (-f.severity.rank, -f.last_seen.timestamp()))
        result.findings = findings
        return result
