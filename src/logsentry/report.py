"""Reporters: coloured terminal output, JSON, and a self-contained HTML report."""

from __future__ import annotations

import html
import json
import os
import sys

from .engine import AnalysisResult
from .enrich import lookup
from .models import Finding, Severity, plural

_ANSI = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;37m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

_HEX = {
    Severity.CRITICAL: "#c0392b",
    Severity.HIGH: "#d35400",
    Severity.MEDIUM: "#b7791f",
    Severity.LOW: "#2b6cb0",
    Severity.INFO: "#4a5568",
}


def _supports_color() -> bool:
    """Colour only when attached to a real TTY and not disabled via env."""
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def render_terminal(result: AnalysisResult, use_color: bool | None = None) -> str:
    """Human-readable summary for the console."""
    color = _supports_color() if use_color is None else use_color

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines: list[str] = []
    width = 78
    lines.append("=" * width)
    lines.append(paint("  LogSentry — log analysis report", _BOLD))
    lines.append("=" * width)

    span = result.time_range
    lines.append(f"  Files analysed : {', '.join(result.files_analyzed) or 'n/a'}")
    lines.append(f"  Events parsed  : {result.event_count:,} ({result.parse_errors:,} skipped)")
    if span:
        lines.append(f"  Log time range : {span[0]:%Y-%m-%d %H:%M:%S} → {span[1]:%Y-%m-%d %H:%M:%S}")
    lines.append(f"  Findings       : {len(result.findings)}")

    counts = result.severity_counts
    badge = "  ".join(
        paint(f" {sev.value.upper()} {counts[sev.value]} ", _ANSI[sev])
        for sev in reversed(list(Severity))
        if counts[sev.value]
    )
    lines.append(f"  Severity       : {badge or 'none'}")
    lines.append("=" * width)

    if not result.findings:
        lines.append("")
        lines.append("  No findings. Nothing in these logs matched the enabled rules.")
        lines.append("")
        return "\n".join(lines)

    for index, finding in enumerate(result.findings, start=1):
        lines.append("")
        tag = paint(f" {finding.severity.value.upper()} ", _ANSI[finding.severity])
        lines.append(f"[{index:>2}] {tag} {paint(finding.title, _BOLD)}  ({finding.rule_id})")

        location = ""
        if finding.src_ip:
            geo = lookup(finding.src_ip)
            location = f"  [{geo.label}]" if geo and geo.country != "--" else ""
            lines.append(f"     Source    : {finding.src_ip}{location}")
        if finding.users:
            shown = ", ".join(finding.users[:6])
            more = f" (+{len(finding.users) - 6} more)" if len(finding.users) > 6 else ""
            lines.append(f"     Accounts  : {shown}{more}")
        lines.append(
            f"     Window    : {finding.first_seen:%Y-%m-%d %H:%M:%S} → "
            f"{finding.last_seen:%H:%M:%S}  ({plural(finding.event_count, 'event')})"
        )
        if finding.mitre:
            lines.append(f"     ATT&CK    : {'; '.join(finding.mitre)}")

        for chunk in _wrap(finding.description, width - 17):
            lines.append(f"     {chunk}")

        if finding.evidence:
            lines.append(paint("     Evidence:", _DIM) if color else "     Evidence:")
            for raw in finding.evidence[:3]:
                snippet = raw if len(raw) <= width - 12 else raw[: width - 15] + "..."
                lines.append(paint(f"       > {snippet}", _DIM) if color else f"       > {snippet}")

        if finding.recommendation:
            for i, chunk in enumerate(_wrap(finding.recommendation, width - 17)):
                prefix = "     Action    : " if i == 0 else "                 "
                lines.append(f"{prefix}{chunk}" if i == 0 else f"     {chunk}")

    lines.append("")
    lines.append("=" * width)
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    out: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            out.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        out.append(current)
    return out


def render_json(result: AnalysisResult, indent: int = 2) -> str:
    """Machine-readable output, suitable for piping into a SIEM or `jq`."""
    return json.dumps(result.to_dict(), indent=indent)


def _finding_card(finding: Finding, index: int) -> str:
    geo = lookup(finding.src_ip) if finding.src_ip else None
    location = (
        f' <span class="geo">{html.escape(geo.label)}</span>'
        if geo and geo.country != "--"
        else ""
    )
    meta_rows = []
    if finding.src_ip:
        meta_rows.append(("Source IP", f"<code>{html.escape(finding.src_ip)}</code>{location}"))
    if finding.users:
        shown = ", ".join(html.escape(u) for u in finding.users[:10])
        if len(finding.users) > 10:
            shown += f" <span class='muted'>(+{len(finding.users) - 10} more)</span>"
        meta_rows.append(("Accounts", shown))
    meta_rows.append(
        (
            "Window",
            f"{finding.first_seen:%Y-%m-%d %H:%M:%S} &rarr; {finding.last_seen:%H:%M:%S} "
            f"<span class='muted'>({plural(finding.event_count, 'event')})</span>",
        )
    )
    if finding.mitre:
        chips = " ".join(
            f"<span class='chip'>{html.escape(m)}</span>" for m in finding.mitre
        )
        meta_rows.append(("MITRE ATT&CK", chips))

    meta_html = "".join(
        f"<div class='row'><span class='key'>{key}</span><span class='val'>{val}</span></div>"
        for key, val in meta_rows
    )
    evidence_html = "".join(
        f"<li><code>{html.escape(line)}</code></li>" for line in finding.evidence
    )
    recommendation_html = (
        f"<div class='rec'><strong>Recommended action.</strong> "
        f"{html.escape(finding.recommendation)}</div>"
        if finding.recommendation
        else ""
    )

    return f"""
    <article class="finding sev-{finding.severity.value}">
      <header>
        <span class="badge">{finding.severity.value.upper()}</span>
        <h3>{index}. {html.escape(finding.title)}</h3>
        <span class="rule-id">{html.escape(finding.rule_id)}</span>
      </header>
      <div class="meta">{meta_html}</div>
      <p class="desc">{html.escape(finding.description)}</p>
      {recommendation_html}
      <details>
        <summary>Evidence ({plural(len(finding.evidence), 'sample line')})</summary>
        <ul class="evidence">{evidence_html}</ul>
      </details>
    </article>"""


def render_html(result: AnalysisResult, title: str = "LogSentry report") -> str:
    """A single self-contained HTML file — no external CSS, JS or fonts."""
    counts = result.severity_counts
    span = result.time_range

    total = max(len(result.findings), 1)
    bar_segments = "".join(
        f"<div class='seg' style='width:{counts[s.value] / total * 100:.2f}%;"
        f"background:{_HEX[s]}' title='{s.value}: {counts[s.value]}'></div>"
        for s in reversed(list(Severity))
        if counts[s.value]
    )

    stat_tiles = "".join(
        f"""<div class="tile"><span class="num" style="color:{_HEX[s]}">{counts[s.value]}</span>
        <span class="lbl">{s.value}</span></div>"""
        for s in reversed(list(Severity))
    )

    cards = "".join(
        _finding_card(f, i) for i, f in enumerate(result.findings, start=1)
    ) or "<p class='empty'>No findings. Nothing in these logs matched the enabled rules.</p>"

    range_text = (
        f"{span[0]:%Y-%m-%d %H:%M} &rarr; {span[1]:%Y-%m-%d %H:%M}" if span else "n/a"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{
    --bg: #f7f8fa; --card: #ffffff; --ink: #1a202c; --muted: #718096;
    --line: #e2e8f0; --accent: #2b6cb0;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#12151a; --card:#1a1f27; --ink:#e8eaed; --muted:#9aa5b1;
             --line:#2d3542; --accent:#63a4ff; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.6
         -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-size: 26px; margin: 0 0 4px; letter-spacing:-.02em; }}
  .sub {{ color: var(--muted); font-size: 14px; margin-bottom: 24px; }}
  .panel {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
            padding:20px; margin-bottom:24px; }}
  .stats {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px; }}
  .tile {{ flex:1 1 90px; text-align:center; padding:12px 8px; border:1px solid var(--line);
           border-radius:10px; }}
  .tile .num {{ display:block; font-size:26px; font-weight:700; line-height:1.1; }}
  .tile .lbl {{ font-size:11px; text-transform:uppercase; letter-spacing:.08em;
                color:var(--muted); }}
  .bar {{ display:flex; height:10px; border-radius:6px; overflow:hidden;
          background:var(--line); }}
  .bar .seg {{ height:100%; }}
  dl.facts {{ display:grid; grid-template-columns:auto 1fr; gap:6px 18px; margin:16px 0 0;
              font-size:14px; }}
  dl.facts dt {{ color:var(--muted); }}
  dl.facts dd {{ margin:0; }}
  .finding {{ background:var(--card); border:1px solid var(--line); border-left-width:5px;
              border-radius:10px; padding:16px 18px; margin-bottom:14px; }}
  .finding.sev-critical {{ border-left-color:{_HEX[Severity.CRITICAL]}; }}
  .finding.sev-high     {{ border-left-color:{_HEX[Severity.HIGH]}; }}
  .finding.sev-medium   {{ border-left-color:{_HEX[Severity.MEDIUM]}; }}
  .finding.sev-low      {{ border-left-color:{_HEX[Severity.LOW]}; }}
  .finding.sev-info     {{ border-left-color:{_HEX[Severity.INFO]}; }}
  .finding header {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .finding h3 {{ font-size:16px; margin:0; flex:1 1 auto; }}
  .badge {{ font-size:10px; font-weight:700; letter-spacing:.08em; color:#fff;
            padding:3px 8px; border-radius:20px; }}
  .sev-critical .badge {{ background:{_HEX[Severity.CRITICAL]}; }}
  .sev-high     .badge {{ background:{_HEX[Severity.HIGH]}; }}
  .sev-medium   .badge {{ background:{_HEX[Severity.MEDIUM]}; }}
  .sev-low      .badge {{ background:{_HEX[Severity.LOW]}; }}
  .sev-info     .badge {{ background:{_HEX[Severity.INFO]}; }}
  .rule-id {{ font-size:12px; color:var(--muted); font-family:ui-monospace,monospace; }}
  .meta {{ margin:12px 0; font-size:13px; }}
  .meta .row {{ display:flex; gap:12px; padding:2px 0; }}
  .meta .key {{ min-width:110px; color:var(--muted); }}
  .desc {{ margin:10px 0; }}
  .rec {{ background:rgba(43,108,176,.09); border-radius:8px; padding:10px 12px;
          font-size:14px; margin:10px 0; }}
  .chip {{ display:inline-block; background:var(--line); border-radius:5px;
           padding:2px 7px; font-size:11px; margin:2px 3px 2px 0; }}
  .geo {{ color:var(--muted); font-size:12px; }}
  .muted {{ color:var(--muted); }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; }}
  details summary {{ cursor:pointer; color:var(--accent); font-size:13px; }}
  ul.evidence {{ list-style:none; padding:10px 0 0; margin:0; }}
  ul.evidence li {{ background:var(--bg); border:1px solid var(--line); border-radius:6px;
                    padding:6px 9px; margin-bottom:5px; overflow-x:auto;
                    white-space:pre; }}
  .empty {{ text-align:center; color:var(--muted); padding:40px; }}
  footer {{ color:var(--muted); font-size:12px; text-align:center; margin-top:32px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>LogSentry report</h1>
  <p class="sub">Generated {result.started_at:%Y-%m-%d %H:%M:%S}</p>

  <section class="panel">
    <div class="stats">{stat_tiles}</div>
    <div class="bar">{bar_segments}</div>
    <dl class="facts">
      <dt>Files analysed</dt><dd>{html.escape(', '.join(result.files_analyzed) or 'n/a')}</dd>
      <dt>Events parsed</dt><dd>{result.event_count:,} <span class="muted">({result.parse_errors:,} lines skipped)</span></dd>
      <dt>Log time range</dt><dd>{range_text}</dd>
      <dt>Total findings</dt><dd>{len(result.findings)}</dd>
      <dt>Source IPs flagged</dt><dd>{len(result.unique_attacker_ips)}</dd>
    </dl>
  </section>

  <h2 style="font-size:18px;margin:0 0 12px;">Findings</h2>
  {cards}

  <footer>Produced by LogSentry &middot; findings are indicators, not verdicts &mdash; verify before acting.</footer>
</div>
</body>
</html>"""


def write_report(result: AnalysisResult, path: str, fmt: str) -> None:
    """Write ``result`` to ``path`` in the requested format."""
    renderers = {
        "json": render_json,
        "html": render_html,
        "text": lambda r: render_terminal(r, use_color=False),
    }
    if fmt not in renderers:
        raise ValueError(f"Unknown report format: {fmt}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(renderers[fmt](result))
