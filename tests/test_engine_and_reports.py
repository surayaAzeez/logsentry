"""End-to-end tests: engine wiring, report rendering and the CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from logsentry import Engine, render_html, render_json, render_terminal
from logsentry.cli import main
from logsentry.enrich import haversine_km, lookup
from logsentry.models import Severity

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_AUTH = REPO_ROOT / "data" / "auth.log"
SAMPLE_ACCESS = REPO_ROOT / "data" / "access.log"

needs_samples = pytest.mark.skipif(
    not SAMPLE_AUTH.exists(),
    reason="run `python scripts/generate_sample_logs.py --out data/` first",
)


class TestEnrichment:
    def test_known_range_resolves(self):
        info = lookup("212.83.44.18")
        assert info is not None
        assert info.country == "QA"

    def test_private_ip_is_marked_internal(self):
        info = lookup("10.0.4.7")
        assert info is not None
        assert info.country == "--"

    def test_unknown_public_ip_returns_none(self):
        assert lookup("8.8.4.4") is None

    def test_reserved_documentation_range_counts_as_internal(self):
        # 203.0.113.0/24 is TEST-NET-3, which ipaddress reports as private.
        info = lookup("203.0.113.7")
        assert info is not None
        assert info.country == "--"

    def test_invalid_ip_returns_none(self):
        assert lookup("not-an-ip") is None

    def test_haversine_doha_to_sao_paulo(self):
        # Real-world great-circle distance is ~11,900 km.
        distance = haversine_km(25.2854, 51.5310, -23.5505, -46.6333)
        assert 11_000 < distance < 12_800

    def test_haversine_zero_distance(self):
        assert haversine_km(25.0, 51.0, 25.0, 51.0) == pytest.approx(0.0)


class TestEngine:
    def test_findings_sorted_by_severity(self, sample_auth_log, sample_access_log):
        result = Engine().analyze_files([sample_auth_log, sample_access_log])
        ranks = [f.severity.rank for f in result.findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_min_severity_filters(self, sample_auth_log, sample_access_log):
        everything = Engine().analyze_files([sample_auth_log, sample_access_log])
        high_only = Engine(min_severity=Severity.HIGH).analyze_files(
            [sample_auth_log, sample_access_log]
        )

        assert len(high_only.findings) <= len(everything.findings)
        assert all(f.severity.rank >= Severity.HIGH.rank for f in high_only.findings)

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            Engine().analyze_files(["/nonexistent/auth.log"])

    def test_result_serialises_to_json(self, sample_access_log):
        result = Engine().analyze_files([sample_access_log])
        payload = json.loads(render_json(result))

        assert "summary" in payload
        assert payload["summary"]["total_findings"] == len(result.findings)
        assert isinstance(payload["findings"], list)

    def test_severity_counts_cover_every_level(self, sample_access_log):
        result = Engine().analyze_files([sample_access_log])
        assert set(result.severity_counts) == {s.value for s in Severity}


class TestReports:
    def test_terminal_report_mentions_findings(self, sample_access_log):
        result = Engine().analyze_files([sample_access_log])
        text = render_terminal(result, use_color=False)

        assert "LogSentry" in text
        assert "\033[" not in text  # no ANSI when colour is off
        for finding in result.findings:
            assert finding.rule_id in text

    def test_terminal_report_handles_zero_findings(self, tmp_path):
        empty = tmp_path / "empty.log"
        empty.write_text("nothing to see here\n", encoding="utf-8")
        text = render_terminal(Engine().analyze_files([empty]), use_color=False)

        assert "No findings" in text

    def test_html_report_is_self_contained(self, sample_access_log):
        result = Engine().analyze_files([sample_access_log])
        page = render_html(result)

        assert page.startswith("<!doctype html>")
        assert "<style>" in page
        assert "<script" not in page  # no JS, no external fetches
        assert "src=\"http" not in page

    def test_html_escapes_injected_markup(self, tmp_path):
        """A crafted log line must not be able to inject HTML into the report."""
        path = tmp_path / "access.log"
        payload = "/<script>alert(1)</script>/.env"
        lines = [
            f'89.248.165.72 - - [11/Mar/2025:05:12:0{i} +0000] '
            f'"GET {payload} HTTP/1.1" 200 100 "-" "Go-http-client/2.0"'
            for i in range(4)
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        page = render_html(Engine().analyze_files([path]))

        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page


class TestCLI:
    def test_scan_exits_1_when_findings_exist(self, sample_auth_log, capsys):
        code = main(["scan", str(sample_auth_log), "--year", "2025"])
        captured = capsys.readouterr()

        assert code == 1
        assert "LogSentry" in captured.out

    def test_scan_exits_0_on_clean_log(self, tmp_path):
        clean = tmp_path / "clean.log"
        clean.write_text(
            "Mar 11 10:20:41 web-01 sshd[1]: Accepted publickey for deploy "
            "from 10.0.4.7 port 42011 ssh2\n",
            encoding="utf-8",
        )
        assert main(["scan", str(clean), "--quiet", "--year", "2025"]) == 0

    def test_missing_file_exits_2(self, capsys):
        assert main(["scan", "/nope/auth.log", "--quiet"]) == 2
        assert "not found" in capsys.readouterr().err

    def test_fail_on_gate(self, sample_auth_log):
        """--fail-on critical must not trip on a medium-severity finding."""
        code = main(
            ["scan", str(sample_auth_log), "--quiet", "--year", "2025",
             "--fail-on", "critical"]
        )
        assert code == 0

    def test_writes_json_and_html(self, sample_access_log, tmp_path):
        json_path = tmp_path / "out.json"
        html_path = tmp_path / "out.html"
        main([
            "scan", str(sample_access_log), "--quiet",
            "--json", str(json_path), "--html", str(html_path),
        ])

        assert json.loads(json_path.read_text())["summary"]["total_findings"] >= 1
        assert "<!doctype html>" in html_path.read_text()

    def test_rules_subcommand_lists_every_rule(self, capsys):
        assert main(["rules"]) == 0
        out = capsys.readouterr().out
        for rule_id in ("LS-001", "LS-002", "LS-003", "LS-004", "LS-005", "LS-006", "LS-007"):
            assert rule_id in out

    def test_module_entrypoint_runs(self):
        proc = subprocess.run(
            [sys.executable, "-m", "logsentry.cli", "rules"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0
        assert "LS-001" in proc.stdout


@needs_samples
class TestAgainstGeneratedSamples:
    """Guards the numbers quoted in the README against the shipped sample data."""

    def test_every_planted_attack_is_detected(self):
        result = Engine().analyze_files([SAMPLE_AUTH, SAMPLE_ACCESS], year=2025)
        found = {f.rule_id for f in result.findings}

        assert {"LS-001", "LS-002", "LS-003", "LS-004", "LS-005", "LS-006", "LS-007"} <= found

    def test_brute_force_attack_ip_is_identified(self):
        result = Engine().analyze_files([SAMPLE_AUTH], year=2025)
        brute = [f for f in result.findings if f.rule_id == "LS-001"]

        assert brute
        assert brute[0].src_ip == "45.83.12.9"
        assert brute[0].severity is Severity.CRITICAL  # the attack succeeded

    def test_benign_long_haul_flight_is_not_flagged(self):
        result = Engine().analyze_files([SAMPLE_AUTH], year=2025)
        travel = [f for f in result.findings if f.rule_id == "LS-003"]

        assert [f.users for f in travel] == [["j.okoro"]]
