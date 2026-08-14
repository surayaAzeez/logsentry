"""LogSentry — a blue-team log analysis and threat detection engine.

Parses authentication and web server logs, runs detection rules over the
normalised events, and reports findings mapped to MITRE ATT&CK techniques.

Quick start::

    from logsentry import Engine, render_terminal

    result = Engine().analyze_files(["data/auth.log"])
    print(render_terminal(result))
"""

__version__ = "0.1.0"

from .engine import AnalysisResult, Engine
from .models import EventType, Finding, LogEvent, Severity
from .report import render_html, render_json, render_terminal, write_report

__all__ = [
    "__version__",
    "Engine",
    "AnalysisResult",
    "LogEvent",
    "Finding",
    "Severity",
    "EventType",
    "render_terminal",
    "render_json",
    "render_html",
    "write_report",
]
