"""Brute-force and password-spray detections.

The two are mirror images of each other:

* **Brute force** - many passwords against *few* accounts from one IP.
* **Password spray** - a few common passwords against *many* accounts, which
  stays under per-account lockout thresholds and so evades naive counting.

Both also check whether the burst was followed by a success, which is the
difference between "noise from the internet" and "you have an incident".
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from ..models import EventType, Finding, LogEvent, Severity, plural
from .base import Rule, register_rule, sliding_window


@register_rule
class BruteForceRule(Rule):
    """Many authentication failures from a single source IP in a short window."""

    rule_id = "LS-001"
    title = "SSH brute-force attempt"
    mitre = ["T1110.001 - Brute Force: Password Guessing"]
    defaults = {
        "threshold": 10,
        "window_minutes": 5,
    }

    def run(self, events: Sequence[LogEvent]) -> list[Finding]:
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for event in events:
            if event.is_failure and event.src_ip:
                by_ip[event.src_ip].append(event)

        window = timedelta(minutes=self.window_minutes)
        findings: list[Finding] = []

        for ip, failures in by_ip.items():
            failures.sort(key=lambda e: e.timestamp)
            for burst in sliding_window(failures, window, self.threshold):
                users = sorted({e.user for e in burst if e.user})
                compromised = self._succeeded_after(events, ip, burst[0].timestamp)

                if compromised:
                    severity = Severity.CRITICAL
                elif len(burst) >= self.threshold * 5:
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                rate = len(burst) / max(
                    (burst[-1].timestamp - burst[0].timestamp).total_seconds(), 1
                )
                description = (
                    f"{len(burst)} failed authentications from {ip} "
                    f"in {(burst[-1].timestamp - burst[0].timestamp).total_seconds():.0f}s "
                    f"({rate * 60:.1f}/min) targeting {plural(len(users), 'account')}."
                )
                if compromised:
                    description += (
                        f" A SUCCESSFUL login from this IP followed as "
                        f"'{compromised.user}' at {compromised.timestamp:%Y-%m-%d %H:%M:%S} "
                        f"- treat as a confirmed compromise."
                    )

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title
                        + (" with successful login" if compromised else ""),
                        severity=severity,
                        description=description,
                        first_seen=burst[0].timestamp,
                        last_seen=burst[-1].timestamp,
                        src_ip=ip,
                        users=users,
                        event_count=len(burst),
                        mitre=self.mitre,
                        evidence=[e.raw for e in burst],
                        recommendation=(
                            "Isolate the account and rotate its credentials, then block "
                            f"{ip} at the firewall and review what the session touched."
                            if compromised
                            else f"Block {ip}, and confirm fail2ban/rate limiting is "
                            "active on this host."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _succeeded_after(
        events: Sequence[LogEvent], ip: str, after: object
    ) -> LogEvent | None:
        """Return the first successful login from ``ip`` at or after ``after``."""
        for event in events:
            if (
                event.src_ip == ip
                and event.event_type == EventType.AUTH_SUCCESS
                and event.timestamp >= after  # type: ignore[operator]
            ):
                return event
        return None


@register_rule
class PasswordSprayRule(Rule):
    """One source IP probing many distinct accounts with few attempts each.

    Deliberately looks at *account breadth* rather than attempt volume, so it
    fires on the low-and-slow pattern that :class:`BruteForceRule` misses.
    """

    rule_id = "LS-002"
    title = "Password spraying across multiple accounts"
    mitre = ["T1110.003 - Brute Force: Password Spraying"]
    defaults = {
        "min_users": 8,
        "window_minutes": 30,
        "max_attempts_per_user": 3,
    }

    @staticmethod
    def _attempts_per_user(span: Sequence[LogEvent]) -> dict[str, int]:
        """Count distinct *attempts* per account, not distinct log lines.

        One failed SSH attempt against an unknown account emits two lines —
        ``Invalid user bob ...`` and ``Failed password for invalid user bob ...``
        — sharing a source port. Counting lines therefore doubles every attempt
        and pushes a genuine spray over ``max_attempts_per_user``, silencing the
        rule on exactly the data it exists to catch. Deduplicating on
        ``(user, src_port)`` collapses the pair back into one attempt; where no
        port is recorded we fall back to the timestamp.
        """
        seen: dict[str, set[object]] = defaultdict(set)
        for event in span:
            key = event.src_port if event.src_port is not None else event.timestamp
            seen[str(event.user)].add(key)
        return {user: len(keys) for user, keys in seen.items()}

    def run(self, events: Sequence[LogEvent]) -> list[Finding]:
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for event in events:
            if event.is_failure and event.src_ip and event.user:
                by_ip[event.src_ip].append(event)

        window = timedelta(minutes=self.window_minutes)
        findings: list[Finding] = []

        for ip, failures in by_ip.items():
            failures.sort(key=lambda e: e.timestamp)

            # Sweep every window and keep the one covering the most accounts.
            # Emitting on the *first* qualifying window would report only the
            # first `min_users` accounts and understate the spray's breadth.
            best: tuple[list[LogEvent], dict[str, int]] | None = None
            start = 0
            for end in range(len(failures)):
                while failures[end].timestamp - failures[start].timestamp > window:
                    start += 1
                span = failures[start : end + 1]
                per_user = self._attempts_per_user(span)

                if len(per_user) < self.min_users:
                    continue
                # High per-account counts mean this is brute force, not spraying.
                if max(per_user.values()) > self.max_attempts_per_user:
                    continue
                if best is None or len(per_user) > len(best[1]):
                    best = (span, per_user)

            if best is None:
                continue

            span, per_user = best
            users = sorted(per_user)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    description=(
                        f"{ip} attempted authentication against {len(users)} distinct "
                        f"accounts with at most {plural(max(per_user.values()), 'attempt')} each "
                        f"over {(span[-1].timestamp - span[0].timestamp).total_seconds() / 60:.0f} "
                        "minutes. Low per-account volume of this kind is designed to "
                        "stay below lockout thresholds."
                    ),
                    first_seen=span[0].timestamp,
                    last_seen=span[-1].timestamp,
                    src_ip=ip,
                    users=users,
                    event_count=len(span),
                    mitre=self.mitre,
                    evidence=[e.raw for e in span],
                    recommendation=(
                        "Check whether any of the sprayed accounts logged in "
                        "successfully, enforce MFA, and add source-based rate limiting."
                    ),
                )
            )
        return findings
