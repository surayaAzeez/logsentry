"""HTTP-layer detections for the nginx/Apache access log.

Covers the two things that dominate a public web server's log: automated
vulnerability scanning, and attempts to reach files that should never be
requested over HTTP.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from ..models import EventType, Finding, LogEvent, Severity, plural
from .base import Rule, register_rule

_SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus|"
    r"zgrab|python-requests|curl/|libwww-perl|hydra|feroxbuster)",
    re.IGNORECASE,
)

_SUSPICIOUS_PATHS = re.compile(
    r"(\.\./|%2e%2e|/etc/passwd|/\.env|/\.git/|/wp-login|/wp-admin|"
    r"/phpmyadmin|/admin/config|/\.aws/|/\.ssh/|union\s+select|<script|"
    r"/actuator/|/config\.php|\.bak$|\.sql$)",
    re.IGNORECASE,
)


@register_rule
class WebScannerRule(Rule):
    """Automated scanning: known tool user-agents, or a burst of 404s."""

    rule_id = "LS-006"
    title = "Automated web vulnerability scanning"
    mitre = ["T1595.002 - Active Scanning: Vulnerability Scanning"]
    defaults = {
        "not_found_threshold": 15,
        "window_minutes": 2,
    }

    def run(self, events: Sequence[LogEvent]) -> list[Finding]:
        http = [e for e in events if e.event_type == EventType.HTTP_REQUEST]
        if not http:
            return []

        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for event in http:
            if event.src_ip:
                by_ip[event.src_ip].append(event)

        window = timedelta(minutes=self.window_minutes)
        findings: list[Finding] = []

        for ip, requests in by_ip.items():
            requests.sort(key=lambda e: e.timestamp)
            agents = {
                str(e.metadata.get("user_agent", ""))
                for e in requests
                if _SCANNER_AGENTS.search(str(e.metadata.get("user_agent", "")))
            }
            not_found = [e for e in requests if e.metadata.get("status") == 404]

            burst = self._max_burst(not_found, window)
            flagged_by_agent = bool(agents)
            flagged_by_volume = burst >= self.not_found_threshold
            if not (flagged_by_agent or flagged_by_volume):
                continue

            reasons = []
            if flagged_by_agent:
                reasons.append(f"scanner {plural(len(agents), 'user-agent')}: {', '.join(sorted(agents))}")
            if flagged_by_volume:
                reasons.append(
                    f"{burst} HTTP 404s within {plural(self.window_minutes, 'minute')}"
                )

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    # A named tool is a much stronger signal than 404 volume alone.
                    severity=Severity.MEDIUM if flagged_by_agent else Severity.LOW,
                    description=(
                        f"{ip} issued {len(requests)} requests showing signs of "
                        f"automated scanning — {'; '.join(reasons)}. Scanning usually "
                        "precedes exploitation attempts."
                    ),
                    first_seen=requests[0].timestamp,
                    last_seen=requests[-1].timestamp,
                    src_ip=ip,
                    event_count=len(requests),
                    mitre=self.mitre,
                    evidence=[e.raw for e in requests],
                    recommendation=(
                        f"Rate-limit or block {ip} at the WAF/edge, and verify that "
                        "any endpoint it reached with a 200 is meant to be public."
                    ),
                )
            )
        return findings

    @staticmethod
    def _max_burst(events: Sequence[LogEvent], window: timedelta) -> int:
        """Largest number of events falling inside any single ``window``."""
        if not events:
            return 0
        best = 0
        start = 0
        for end in range(len(events)):
            while events[end].timestamp - events[start].timestamp > window:
                start += 1
            best = max(best, end - start + 1)
        return best


@register_rule
class SensitivePathProbeRule(Rule):
    """Requests for paths that map to traversal, secrets or injection attempts."""

    rule_id = "LS-007"
    title = "Probing for sensitive paths and injection payloads"
    mitre = [
        "T1190 - Exploit Public-Facing Application",
        "T1083 - File and Directory Discovery",
    ]
    defaults = {"min_hits": 3}

    def run(self, events: Sequence[LogEvent]) -> list[Finding]:
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for event in events:
            if event.event_type != EventType.HTTP_REQUEST or not event.src_ip:
                continue
            path = str(event.metadata.get("path", ""))
            if _SUSPICIOUS_PATHS.search(path):
                by_ip[event.src_ip].append(event)

        findings: list[Finding] = []
        for ip, hits in by_ip.items():
            if len(hits) < self.min_hits:
                continue
            hits.sort(key=lambda e: e.timestamp)

            # A 200 on a traversal/secrets path means the probe likely worked.
            successful = [e for e in hits if 200 <= int(e.metadata.get("status", 0)) < 300]
            paths = sorted({str(e.metadata.get("path", "")) for e in hits})

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title
                    + (" — server responded 200" if successful else ""),
                    severity=Severity.CRITICAL if successful else Severity.MEDIUM,
                    description=(
                        f"{ip} requested {len(hits)} sensitive paths including "
                        f"{', '.join(paths[:4])}"
                        + (" ..." if len(paths) > 4 else "")
                        + (
                            f". {len(successful)} of these returned a 2xx status, "
                            "meaning content was served — assume exposure until proven "
                            "otherwise."
                            if successful
                            else ". All were rejected by the server."
                        )
                    ),
                    first_seen=hits[0].timestamp,
                    last_seen=hits[-1].timestamp,
                    src_ip=ip,
                    event_count=len(hits),
                    mitre=self.mitre,
                    evidence=[e.raw for e in (successful or hits)],
                    recommendation=(
                        "Verify what was served, rotate any credentials in the exposed "
                        "file, and confirm dotfiles are blocked at the web server."
                        if successful
                        else f"Block {ip} and confirm .git/.env paths return 403/404."
                    ),
                )
            )
        return findings
