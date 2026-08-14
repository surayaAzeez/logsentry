"""Impossible-travel detection.

Two successful logins for the same account from locations far enough apart that
no commercial flight could cover the distance in the elapsed time. This is a
strong signal for credential theft, because it needs no failure events at all —
the attacker may have valid credentials and never trip a brute-force rule.

Caveat worth stating out loud: VPNs and mobile carrier NAT produce false
positives, which is why the finding text names that possibility rather than
asserting compromise.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from ..enrich import haversine_km, lookup
from ..models import EventType, Finding, LogEvent, Severity
from .base import Rule, register_rule


@register_rule
class ImpossibleTravelRule(Rule):
    """Same user, two successful logins, implied speed above a plausible limit."""

    rule_id = "LS-003"
    title = "Impossible travel between successful logins"
    mitre = ["T1078 - Valid Accounts"]
    defaults = {
        # ~900 km/h cruise, padded for the fact that we only have city centroids.
        "max_speed_kmh": 900.0,
        "min_distance_km": 500.0,
    }

    def run(self, events: Sequence[LogEvent]) -> list[Finding]:
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for event in events:
            if (
                event.event_type == EventType.AUTH_SUCCESS
                and event.user
                and event.is_external
            ):
                by_user[event.user].append(event)

        findings: list[Finding] = []
        for user, logins in by_user.items():
            logins.sort(key=lambda e: e.timestamp)
            # Consecutive pairs; strict=False because the slices differ by one.
            for previous, current in zip(logins, logins[1:], strict=False):
                if previous.src_ip == current.src_ip:
                    continue

                geo_a = lookup(str(previous.src_ip))
                geo_b = lookup(str(current.src_ip))
                if not geo_a or not geo_b or geo_a.country == "--" or geo_b.country == "--":
                    continue

                distance = haversine_km(
                    geo_a.latitude, geo_a.longitude, geo_b.latitude, geo_b.longitude
                )
                if distance < self.min_distance_km:
                    continue

                hours = (current.timestamp - previous.timestamp).total_seconds() / 3600
                # Simultaneous logins from two cities are infinitely fast, not undefined.
                speed = float("inf") if hours <= 0 else distance / hours
                if speed <= self.max_speed_kmh:
                    continue

                speed_text = "instantaneous" if hours <= 0 else f"{speed:,.0f} km/h"
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        description=(
                            f"Account '{user}' logged in from {geo_a.label} "
                            f"({previous.src_ip}) and then {geo_b.label} "
                            f"({current.src_ip}) {hours * 60:.0f} minutes later — "
                            f"{distance:,.0f} km apart, an implied travel speed of "
                            f"{speed_text}. A VPN or mobile carrier NAT can explain "
                            "this; credential theft can too."
                        ),
                        first_seen=previous.timestamp,
                        last_seen=current.timestamp,
                        src_ip=current.src_ip,
                        users=[user],
                        event_count=2,
                        mitre=self.mitre,
                        evidence=[previous.raw, current.raw],
                        recommendation=(
                            f"Confirm with the account owner whether they were in "
                            f"{geo_b.label}. If not, revoke active sessions, rotate "
                            "credentials and audit actions taken from the second IP."
                        ),
                    )
                )
        return findings
