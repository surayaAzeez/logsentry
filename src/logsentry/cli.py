"""Command-line interface.

    logsentry scan data/auth.log
    logsentry scan data/*.log --html report.html --min-severity high
    logsentry scan data/auth.log --format sshd --json - | jq '.summary'
    logsentry rules
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .detections import RULES
from .engine import Engine
from .models import Severity, plural
from .parsers import PARSERS
from .report import render_json, render_terminal, write_report

# Exit codes let CI pipelines gate on findings, which is the main reason to
# wire this into an automated workflow at all.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description="Parse authentication and web logs, and flag likely attacks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version=f"logsentry {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Analyse one or more log files")
    scan.add_argument("paths", nargs="+", help="Log files to analyse (.gz supported)")
    scan.add_argument(
        "--format",
        choices=sorted(PARSERS),
        help="Force a parser instead of auto-detecting",
    )
    scan.add_argument(
        "--year",
        type=int,
        help="Year to assume for syslog timestamps, which omit it (default: current)",
    )
    scan.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default="info",
        help="Suppress findings below this severity (default: info)",
    )
    scan.add_argument("--json", metavar="PATH", help="Write JSON report ('-' for stdout)")
    scan.add_argument("--html", metavar="PATH", help="Write a self-contained HTML report")
    scan.add_argument("--quiet", action="store_true", help="Suppress terminal output")
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Exit 1 only if a finding at or above this severity exists",
    )

    scan.add_argument("--threshold", type=int, help="Brute-force: failures per window")
    scan.add_argument("--window-minutes", type=int, help="Brute-force: window size")
    scan.add_argument("--min-users", type=int, help="Password spray: distinct accounts")
    scan.add_argument(
        "--business-hours",
        metavar="START-END",
        help="Off-hours rule working day, e.g. 8-18",
    )

    sub.add_parser("rules", help="List the detection rules that are loaded")
    return parser


def _rule_options(args: argparse.Namespace) -> dict[str, object]:
    """Turn CLI flags into the shared per-rule options dict."""
    options: dict[str, object] = {}
    if args.threshold is not None:
        options["threshold"] = args.threshold
    if args.window_minutes is not None:
        options["window_minutes"] = args.window_minutes
    if args.min_users is not None:
        options["min_users"] = args.min_users
    if args.business_hours:
        try:
            start, end = (int(p) for p in args.business_hours.split("-", 1))
        except ValueError as exc:
            raise SystemExit("--business-hours must look like 8-18") from exc
        options["business_start_hour"] = start
        options["business_end_hour"] = end
    return options


def _cmd_rules() -> int:
    print(f"{plural(len(RULES), 'detection rule')} loaded:\n")
    for cls in sorted(RULES, key=lambda c: c.rule_id):
        print(f"  {cls.rule_id}  {cls.title}")
        for technique in cls.mitre:
            print(f"           ATT&CK: {technique}")
        if cls.defaults:
            tunables = ", ".join(f"{k}={v}" for k, v in cls.defaults.items() if k != "commands")
            if tunables:
                print(f"           Tunables: {tunables}")
        print()
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    paths = [Path(p) for p in args.paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print(f"error: file(s) not found: {', '.join(missing)}", file=sys.stderr)
        return EXIT_ERROR

    engine = Engine(
        rule_options=_rule_options(args),
        min_severity=Severity(args.min_severity),
    )
    result = engine.analyze_files(paths, fmt=args.format, year=args.year)

    if not args.quiet:
        print(render_terminal(result))

    if args.json:
        if args.json == "-":
            print(render_json(result))
        else:
            write_report(result, args.json, "json")
            print(f"JSON report written to {args.json}", file=sys.stderr)

    if args.html:
        write_report(result, args.html, "html")
        print(f"HTML report written to {args.html}", file=sys.stderr)

    if args.fail_on:
        gate = Severity(args.fail_on)
        if any(f.severity.rank >= gate.rank for f in result.findings):
            return EXIT_FINDINGS
        return EXIT_OK
    return EXIT_FINDINGS if result.findings else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return _cmd_rules()
    if args.command == "scan":
        try:
            return _cmd_scan(args)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
