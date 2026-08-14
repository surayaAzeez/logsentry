"""Behavioural detections that key on *when* something happened.

These are lower-confidence than the brute-force rules by design. They exist to
surface things a human should glance at, not to page anyone at 3am.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from ..enrich import lookup
from ..models import EventType, Finding, LogEvent, Severity, plural
from .base import Rule, register_rule

#: Commands that meaningfully change security posture when run as root.
_SENSITIVE_COMMANDS = (
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "useradd",
    "usermod",
    "visudo",
    "iptables",
    "ufw",
    "systemctl stop",
    "auditd",
    "rsyslog",
    "history -c",
    "chattr",
    "authorized_keys",
)


@register_rule
class OffHoursAccessRule(Rule):
    """Successful logins outside configured working hours."""

    rule_id = "LS-004"
    title = "Successful login outside business hours"
    mitre = ["T1078 - Valid Accounts"]
    defaults = {
        "business_start_hour": 7,
        "business_end_hour": 20,
        "external_only": True,
    }

    def run(self, events: Sequence[LogEvent]) -> list[Finding]:
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for event in events:
            if event.event_type != EventType.AUTH_SUCCESS or not event.user:
                continue
            if self.external_only and not event.is_external:
                continue
            hour = event.timestamp.hour
            if self.business_start_hour <= hour < self.business_end_hour:
                continue
            by_user[event.user].append(event)

        findings: list[Finding] = []
        for user, logins in sorted(by_user.items()):
            logins.sort(key=lambda e: e.timestamp)
            ips = sorted({str(e.src_ip) for e in logins if e.src_ip})
            locations = sorted(
                {geo.label for ip in ips if (geo := lookup(ip)) is not None}
            )
            location_text = f" from {', '.join(locations)}" if locations else ""
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.LOW,
                    description=(
                        f"'{user}' authenticated successfully {plural(len(logins), 'time')} "
                        f"outside {self.business_start_hour:02d}:00-"
                        f"{self.business_end_hour:02d}:00{location_text}. "
                        "Benign for on-call staff; worth confirming otherwise."
                    ),
                    first_seen=logins[0].timestamp,
                    last_seen=logins[-1].timestamp,
                    src_ip=ips[0] if ips else None,
                    users=[user],
                    event_count=len(logins),
                    mitre=self.mitre,
                    evidence=[e.raw for e in logins],
                    recommendation=(
                        "Cross-check against the on-call rota before escalating."
                    ),
                )
            )
        return findings


@register_rule
class SuspiciousSudoRule(Rule):
    """Privilege escalation running commands that touch security controls."""

    rule_id = "LS-005"
    title = "Sensitive command executed via sudo"
    mitre = [
        "T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "T1070 - Indicator Removal",
    ]
    defaults = {"commands": list(_SENSITIVE_COMMANDS)}

    def run(self, events: Sequence[LogEvent]) -> list[Finding]:
        hits: dict[str, list[LogEvent]] = defaultdict(list)
        for event in events:
            if event.event_type != EventType.PRIVILEGE_ESCALATION:
                continue
            command = str(event.metadata.get("command", ""))
            if any(needle in command for needle in self.commands):
                hits[str(event.user)].append(event)

        findings: list[Finding] = []
        for user, matched in sorted(hits.items()):
            matched.sort(key=lambda e: e.timestamp)
            commands = sorted({str(e.metadata.get("command", "")) for e in matched})
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    description=(
                        f"'{user}' ran {plural(len(matched), 'sudo command')} affecting "
                        f"credentials, logging or firewall state: "
                        f"{'; '.join(commands[:3])}"
                        + (" ..." if len(commands) > 3 else "")
                    ),
                    first_seen=matched[0].timestamp,
                    last_seen=matched[-1].timestamp,
                    users=[user],
                    event_count=len(matched),
                    mitre=self.mitre,
                    evidence=[e.raw for e in matched],
                    recommendation=(
                        "Match each command against a change ticket. Clearing history "
                        "or stopping auditd immediately after a login is a strong "
                        "anti-forensics signal."
                    ),
                )
            )
        return findings
