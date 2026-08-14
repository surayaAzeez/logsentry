"""Detection rule tests.

Each rule gets a true positive (it fires when it should), a true negative (it
stays quiet on benign data), and where the logic warrants it, an escalation
case. The true negatives matter most — a rule that alerts on everything is
worse than no rule.
"""

from __future__ import annotations

from datetime import timedelta

from conftest import BASE, make_event

from logsentry.detections import (
    BruteForceRule,
    ImpossibleTravelRule,
    OffHoursAccessRule,
    PasswordSprayRule,
    SensitivePathProbeRule,
    SuspiciousSudoRule,
    WebScannerRule,
)
from logsentry.detections.base import sliding_window
from logsentry.models import EventType, LogEvent, Severity


class TestSlidingWindow:
    def test_finds_burst_above_threshold(self):
        events = [make_event(offset_seconds=i * 2) for i in range(10)]
        bursts = sliding_window(events, timedelta(minutes=1), threshold=5)

        assert bursts
        assert len(bursts[0]) >= 5

    def test_no_burst_when_events_are_spread_out(self):
        events = [make_event(offset_seconds=i * 600) for i in range(10)]
        assert sliding_window(events, timedelta(minutes=1), threshold=5) == []

    def test_overlapping_bursts_merge_into_one(self):
        events = [make_event(offset_seconds=i) for i in range(30)]
        bursts = sliding_window(events, timedelta(minutes=5), threshold=10)

        assert len(bursts) == 1
        assert len(bursts[0]) == 30

    def test_empty_input(self):
        assert sliding_window([], timedelta(minutes=5), threshold=1) == []


class TestBruteForce:
    def test_fires_on_rapid_failures(self):
        events = [make_event(offset_seconds=i * 3) for i in range(20)]
        findings = BruteForceRule().run(events)

        assert len(findings) == 1
        assert findings[0].rule_id == "LS-001"
        assert findings[0].src_ip == "45.83.12.9"
        assert findings[0].event_count == 20
        assert findings[0].severity is Severity.MEDIUM

    def test_quiet_on_a_few_typos(self):
        events = [make_event(offset_seconds=i * 30, user="deploy") for i in range(3)]
        assert BruteForceRule().run(events) == []

    def test_quiet_when_failures_are_spread_over_hours(self):
        events = [make_event(offset_seconds=i * 3600) for i in range(20)]
        assert BruteForceRule().run(events) == []

    def test_escalates_to_critical_when_a_login_succeeds(self):
        events = [make_event(offset_seconds=i * 3) for i in range(20)]
        events.append(
            make_event(offset_seconds=100, event_type=EventType.AUTH_SUCCESS)
        )
        findings = BruteForceRule().run(events)

        assert findings[0].severity is Severity.CRITICAL
        assert "compromise" in findings[0].description.lower()

    def test_separate_ips_produce_separate_findings(self):
        events = [make_event(offset_seconds=i * 3, src_ip="45.83.12.9") for i in range(15)]
        events += [make_event(offset_seconds=i * 3, src_ip="103.207.1.1") for i in range(15)]
        findings = BruteForceRule().run(events)

        assert len(findings) == 2
        assert {f.src_ip for f in findings} == {"45.83.12.9", "103.207.1.1"}

    def test_threshold_is_configurable(self):
        events = [make_event(offset_seconds=i * 3) for i in range(6)]

        assert BruteForceRule().run(events) == []
        assert BruteForceRule(threshold=5).run(events)

    def test_evidence_is_capped(self):
        events = [make_event(offset_seconds=i * 2) for i in range(60)]
        finding = BruteForceRule().run(events)[0]

        assert finding.event_count == 60
        assert len(finding.evidence) == 5  # full count kept, evidence trimmed


class TestPasswordSpray:
    def _spray(self, users, attempts_each=2, ip="185.220.101.45"):
        events = []
        for i, user in enumerate(users):
            for attempt in range(attempts_each):
                events.append(
                    make_event(
                        offset_seconds=i * 60 + attempt * 10,
                        event_type=EventType.AUTH_INVALID_USER,
                        user=user,
                        src_ip=ip,
                    )
                )
        return events

    def test_fires_across_many_accounts(self):
        users = [f"user{i}" for i in range(12)]
        findings = PasswordSprayRule().run(self._spray(users))

        assert len(findings) == 1
        assert findings[0].rule_id == "LS-002"
        assert len(findings[0].users) == 12
        assert findings[0].severity is Severity.HIGH

    def test_quiet_on_few_accounts(self):
        findings = PasswordSprayRule().run(self._spray(["alice", "bob", "carol"]))
        assert findings == []

    def test_quiet_when_volume_per_account_is_high(self):
        """That pattern is brute force, and LS-001 owns it."""
        users = [f"user{i}" for i in range(12)]
        findings = PasswordSprayRule().run(self._spray(users, attempts_each=10))
        assert findings == []

    def test_one_finding_per_ip(self):
        users = [f"user{i}" for i in range(20)]
        findings = PasswordSprayRule().run(self._spray(users))
        assert len(findings) == 1


class TestImpossibleTravel:
    def _login(self, offset_hours, ip, user="j.okoro"):
        return LogEvent(
            timestamp=BASE + timedelta(hours=offset_hours),
            source="test",
            event_type=EventType.AUTH_SUCCESS,
            raw=f"Accepted password for {user} from {ip}",
            user=user,
            src_ip=ip,
        )

    def test_fires_on_doha_to_sao_paulo_in_40_minutes(self):
        events = [
            self._login(0, "212.83.44.18"),      # Doha
            self._login(40 / 60, "191.96.77.204"),  # Sao Paulo
        ]
        findings = ImpossibleTravelRule().run(events)

        assert len(findings) == 1
        assert findings[0].rule_id == "LS-003"
        assert findings[0].users == ["j.okoro"]

    def test_quiet_on_a_plausible_long_haul_flight(self):
        events = [
            self._login(0, "82.102.19.4"),       # London
            self._login(14, "156.146.55.12"),    # Singapore, 14h later
        ]
        assert ImpossibleTravelRule().run(events) == []

    def test_quiet_for_same_ip(self):
        events = [self._login(0, "212.83.44.18"), self._login(0.1, "212.83.44.18")]
        assert ImpossibleTravelRule().run(events) == []

    def test_quiet_for_internal_ips(self):
        events = [self._login(0, "10.0.4.7"), self._login(0.1, "192.168.10.22")]
        assert ImpossibleTravelRule().run(events) == []

    def test_different_users_are_not_correlated(self):
        events = [
            self._login(0, "212.83.44.18", user="alice"),
            self._login(40 / 60, "191.96.77.204", user="bob"),
        ]
        assert ImpossibleTravelRule().run(events) == []


class TestOffHours:
    def _login_at(self, hour, ip="45.83.12.9", user="root"):
        return LogEvent(
            timestamp=BASE.replace(hour=hour, minute=47),
            source="test",
            event_type=EventType.AUTH_SUCCESS,
            raw=f"Accepted password for {user} from {ip}",
            user=user,
            src_ip=ip,
        )

    def test_fires_at_0347(self):
        findings = OffHoursAccessRule().run([self._login_at(3)])

        assert len(findings) == 1
        assert findings[0].rule_id == "LS-004"
        assert findings[0].severity is Severity.LOW

    def test_quiet_during_business_hours(self):
        assert OffHoursAccessRule().run([self._login_at(14)]) == []

    def test_quiet_for_internal_source_by_default(self):
        assert OffHoursAccessRule().run([self._login_at(3, ip="10.0.4.7")]) == []

    def test_business_hours_are_configurable(self):
        rule = OffHoursAccessRule(business_start_hour=15, business_end_hour=23)
        assert rule.run([self._login_at(3)])
        assert rule.run([self._login_at(16)]) == []


class TestSuspiciousSudo:
    def _sudo(self, command, user="root", offset=0):
        return make_event(
            offset_seconds=offset,
            event_type=EventType.PRIVILEGE_ESCALATION,
            user=user,
            command=command,
            target_user="root",
        )

    def test_fires_on_shadow_read_and_audit_tampering(self):
        events = [
            self._sudo("/bin/cat /etc/shadow"),
            self._sudo("/usr/bin/systemctl stop auditd", offset=60),
            self._sudo("/bin/bash -c history -c", offset=120),
        ]
        findings = SuspiciousSudoRule().run(events)

        assert len(findings) == 1
        assert findings[0].rule_id == "LS-005"
        assert findings[0].event_count == 3

    def test_quiet_on_ordinary_admin_work(self):
        events = [
            self._sudo("/usr/bin/apt-get update"),
            self._sudo("/bin/ls /var/log", offset=30),
        ]
        assert SuspiciousSudoRule().run(events) == []


class TestWebRules:
    def _request(self, path, status=200, agent="Mozilla/5.0", ip="196.52.43.87", offset=0):
        return make_event(
            offset_seconds=offset,
            event_type=EventType.HTTP_REQUEST,
            user=None,
            src_ip=ip,
            path=path,
            status=status,
            user_agent=agent,
            method="GET",
        )

    def test_scanner_user_agent_is_flagged(self):
        events = [self._request("/wp-login.php", 404, agent="sqlmap/1.7.11")]
        findings = WebScannerRule().run(events)

        assert len(findings) == 1
        assert findings[0].rule_id == "LS-006"
        assert findings[0].severity is Severity.MEDIUM

    def test_404_burst_is_flagged_without_a_known_agent(self):
        events = [
            self._request(f"/admin{i}", 404, offset=i * 2) for i in range(20)
        ]
        findings = WebScannerRule().run(events)

        assert len(findings) == 1
        assert findings[0].severity is Severity.LOW  # weaker signal than a named tool

    def test_quiet_on_normal_browsing(self):
        events = [self._request("/", 200, offset=i * 30) for i in range(10)]
        assert WebScannerRule().run(events) == []

    def test_sensitive_paths_flagged(self):
        events = [
            self._request("/.env", 404, offset=0, ip="89.248.165.72"),
            self._request("/.git/config", 404, offset=10, ip="89.248.165.72"),
            self._request("/api/../../etc/passwd", 400, offset=20, ip="89.248.165.72"),
        ]
        findings = SensitivePathProbeRule().run(events)

        assert len(findings) == 1
        assert findings[0].rule_id == "LS-007"
        assert findings[0].severity is Severity.MEDIUM

    def test_critical_when_sensitive_path_returns_200(self):
        events = [
            self._request("/.env", 200, offset=0, ip="89.248.165.72"),
            self._request("/.git/config", 200, offset=10, ip="89.248.165.72"),
            self._request("/backup.sql", 404, offset=20, ip="89.248.165.72"),
        ]
        findings = SensitivePathProbeRule().run(events)

        assert findings[0].severity is Severity.CRITICAL
        assert "200" in findings[0].title or "2xx" in findings[0].description

    def test_below_min_hits_is_quiet(self):
        events = [self._request("/.env", 404)]
        assert SensitivePathProbeRule().run(events) == []
