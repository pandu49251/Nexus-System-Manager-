"""
nexus_doctor.core.report
========================

Report generation in HTML, Markdown, JSON and plain text.

The HTML report is entirely self-contained: styles are inlined and there are no
external fonts, scripts or images, so it renders identically offline, in an
email attachment, or years later from a backup.  That matters because the
report is what a user takes to a repair shop or a forum when asking for help.

Every finding in a report carries the command that produced it, so any claim in
the document can be independently checked on the machine itself.
"""

from __future__ import annotations

import html
import json
import os
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .models import (CATEGORY_LABELS, Category, Confidence, Evidence, Finding,
                     RepairResult, ScanReport, Severity)
from ..version import APP_NAME, __version__

SEVERITY_COLOURS = {
    "critical": "#b3261e",
    "high": "#c2541b",
    "medium": "#8a6d1f",
    "low": "#3b6ea5",
    "info": "#5a5a5a",
    "ok": "#1f7a3f",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "ok"]


def _esc(text: Any) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def _ts(value: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value)) if value else "n/a"


def _duration(report: ScanReport) -> str:
    if not report.finished:
        return "in progress"
    return f"{report.finished - report.started:.1f} s"


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_HTML_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, "DejaVu Sans", sans-serif; margin: 0; padding: 0;
         background: #f6f7f9; color: #1b1b1b; line-height: 1.5; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
  header {{ background: linear-gradient(135deg, #123a5e, #1d6fa5); color: #fff;
            padding: 22px 24px; border-radius: 10px; }}
  header h1 {{ margin: 0 0 4px; font-size: 21px; letter-spacing: .2px; }}
  header .sub {{ opacity: .85; font-size: 13px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 18px 0; }}
  .card {{ flex: 1 1 110px; background: #fff; border-radius: 8px; padding: 12px;
           border-left: 5px solid #999; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .card .n {{ font-size: 24px; font-weight: 700; }}
  .card .l {{ font-size: 12px; text-transform: uppercase; letter-spacing: .5px; color: #555; }}
  table.meta {{ width: 100%; border-collapse: collapse; background: #fff;
                border-radius: 8px; overflow: hidden; margin-bottom: 18px; }}
  table.meta td {{ padding: 7px 12px; border-bottom: 1px solid #ececec; font-size: 13px; }}
  table.meta td:first-child {{ width: 190px; color: #555; }}
  h2 {{ font-size: 17px; margin: 26px 0 10px; padding-bottom: 6px;
        border-bottom: 2px solid #d9dee3; }}
  .finding {{ background: #fff; border-radius: 8px; margin-bottom: 12px;
              box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow: hidden; }}
  .finding .head {{ padding: 12px 14px; border-left: 6px solid #999; }}
  .finding h3 {{ margin: 0 0 4px; font-size: 15px; }}
  .badge {{ display: inline-block; font-size: 10px; font-weight: 700; color: #fff;
            padding: 2px 7px; border-radius: 10px; vertical-align: 2px; letter-spacing: .4px; }}
  .body {{ padding: 0 14px 14px; font-size: 13.5px; }}
  .body p {{ margin: 8px 0; }}
  .lbl {{ font-weight: 700; color: #333; }}
  ul {{ margin: 6px 0 6px 18px; padding: 0; }}
  li {{ margin: 3px 0; }}
  details {{ margin-top: 8px; border: 1px solid #e6e6e6; border-radius: 6px; }}
  summary {{ cursor: pointer; padding: 7px 10px; font-size: 12.5px;
             background: #fafbfc; font-weight: 600; }}
  .ev {{ padding: 8px 10px; border-top: 1px solid #eee; font-size: 12.5px; }}
  .ev .src {{ font-weight: 600; color: #1d6fa5; }}
  pre {{ background: #f4f6f8; border: 1px solid #e3e7ea; border-radius: 5px;
         padding: 8px; margin: 6px 0 0; overflow-x: auto; font-size: 11.5px;
         font-family: "DejaVu Sans Mono", monospace; white-space: pre-wrap; }}
  code {{ background: #f0f2f4; padding: 1px 4px; border-radius: 3px; font-size: 12px; }}
  footer {{ margin-top: 28px; padding-top: 12px; border-top: 1px solid #d9dee3;
            font-size: 11.5px; color: #666; }}
  .note {{ background: #fff8e1; border-left: 4px solid #e0a800; padding: 10px 12px;
           border-radius: 5px; font-size: 13px; margin: 12px 0; }}
</style></head><body><div class="wrap">
"""


def render_html(report: ScanReport, repairs: Sequence[RepairResult] = ()) -> str:
    counts = report.counts()
    out: List[str] = [_HTML_HEAD.format(
        title=f"{APP_NAME} report - {_esc(report.machine.describe() or report.hostname)}")]

    out.append("<header>")
    out.append(f"<h1>{_esc(APP_NAME)} - System Diagnostic Report</h1>")
    out.append(f"<div class='sub'>Version {_esc(__version__)} &middot; "
               f"generated {_esc(_ts(report.finished or report.started))}</div>")
    out.append("</header>")

    # severity cards
    out.append('<div class="cards">')
    for sev in SEVERITY_ORDER:
        colour = SEVERITY_COLOURS[sev]
        out.append(f'<div class="card" style="border-left-color: {colour}">'
                   f'<div class="n" style="color: {colour}">{counts.get(sev, 0)}</div>'
                   f'<div class="l">{sev}</div></div>')
    out.append("</div>")

    # machine metadata
    out.append("<table class='meta'>")
    meta = [
        ("Machine", report.machine.describe() or "unknown"),
        ("Serial", report.machine.serial or "-"),
        ("BIOS", report.machine.bios_version or "-"),
        ("Distribution", report.distro or "-"),
        ("Desktop", report.desktop or "-"),
        ("Kernel", report.kernel or "-"),
        ("Processor", f"{report.cpu_model} ({report.cpu_cores} cores)"
         if report.cpu_model else "-"),
        ("Memory", f"{report.mem_total_mb} MB" if report.mem_total_mb else "-"),
        ("System disk", report.root_disk or "-"),
        ("Hostname", report.hostname or "-"),
        ("Scan type", "deep" if report.deep else "quick"),
        ("Scan duration", _duration(report)),
        ("Run as", report.run_as or "-"),
    ]
    for key, value in meta:
        out.append(f"<tr><td>{_esc(key)}</td><td>{_esc(value)}</td></tr>")
    out.append("</table>")

    # ordered findings
    findings = report.sorted_findings()
    actionable = [f for f in findings if f.severity.rank <= Severity.LOW.rank]
    if actionable:
        out.append(f"<div class='note'><b>{len(actionable)} finding(s) need attention.</b> "
                   f"They are listed below, most severe first. Each one shows the exact "
                   f"command that produced the evidence, so you can verify it yourself.</div>")

    by_sev: Dict[str, List[Finding]] = {}
    for f in findings:
        by_sev.setdefault(f.severity.value, []).append(f)

    for sev in SEVERITY_ORDER:
        group = by_sev.get(sev, [])
        if not group:
            continue
        colour = SEVERITY_COLOURS[sev]
        out.append(f"<h2>{sev.upper()} ({len(group)})</h2>")
        for f in group:
            out.append('<div class="finding">')
            out.append(f'<div class="head" style="border-left-color: {colour}">'
                       f'<span class="badge" style="background: {colour}">{sev.upper()}</span> '
                       f'<h3 style="display:inline">{_esc(f.title)}</h3>'
                       f'<div class="sub" style="font-size:12px;color:#666">'
                       f'{_esc(CATEGORY_LABELS.get(f.category.value, f.category.value))}'
                       f' &middot; confidence: {_esc(f.confidence.value)}'
                       f' &middot; {_esc(f.id)}</div></div>')
            out.append('<div class="body">')
            out.append(f"<p>{_esc(f.summary)}</p>")
            if f.root_cause:
                out.append(f"<p><span class='lbl'>Likely root cause:</span> {_esc(f.root_cause)}</p>")
            if f.impact:
                out.append(f"<p><span class='lbl'>What you notice:</span> {_esc(f.impact)}</p>")
            if f.recommendations:
                out.append("<p><span class='lbl'>What to do:</span></p><ul>")
                for rec in f.recommendations:
                    out.append(f"<li>{_esc(rec)}</li>")
                out.append("</ul>")
            if f.repair_ids:
                out.append("<p><span class='lbl'>Automatic repair available:</span> "
                           + ", ".join(f"<code>{_esc(r)}</code>" for r in f.repair_ids) + "</p>")
            if f.evidence:
                out.append(f"<details><summary>Evidence ({len(f.evidence)} item(s))</summary>")
                for ev in f.evidence:
                    out.append('<div class="ev">')
                    out.append(f'<div class="src">{_esc(ev.source)}</div>')
                    out.append(f"<div>{_esc(ev.detail)}</div>")
                    if ev.command:
                        out.append(f"<pre>$ {_esc(ev.command)}</pre>")
                    if ev.raw and ev.raw.strip() and len(ev.raw.strip()) < 3000:
                        out.append(f"<pre>{_esc(ev.raw.strip()[:2000])}</pre>")
                    out.append("</div>")
                out.append("</details>")
            out.append("</div></div>")

    # repairs
    if repairs:
        out.append("<h2>Repairs applied</h2>")
        out.append("<table class='meta'><tr><td><b>Repair</b></td>"
                   "<td><b>Result</b></td><td><b>Before</b></td><td><b>After</b></td></tr>")
        for r in repairs:
            colour = "#1f7a3f" if r.state == "verified" else "#b3261e"
            out.append(f"<tr><td>{_esc(r.title)}</td>"
                       f"<td style='color:{colour}'><b>{_esc(r.state)}</b></td>"
                       f"<td>{_esc(r.verify_before[:90])}</td>"
                       f"<td>{_esc(r.verify_after[:90])}</td></tr>")
        out.append("</table>")

    # checks that could not run
    degraded = [r for r in report.results if r.state != "ok"]
    if degraded:
        out.append("<h2>Checks that could not complete</h2><ul>")
        for r in degraded:
            out.append(f"<li><b>{_esc(r.title)}</b>: {_esc(r.state)}"
                       f"{(' - ' + _esc(r.notes)) if r.notes else ''}</li>")
        out.append("</ul>")

    out.append(f"<footer>Generated by {_esc(APP_NAME)} {_esc(__version__)} on "
               f"{_esc(_ts(report.finished or report.started))}. "
               f"Diagnostic data was read from this machine; no data left the system.</footer>")
    out.append("</div></body></html>")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def render_markdown(report: ScanReport, repairs: Sequence[RepairResult] = ()) -> str:
    counts = report.counts()
    out: List[str] = []
    out.append(f"# {APP_NAME} - System Diagnostic Report")
    out.append("")
    out.append(f"*Generated {_ts(report.finished or report.started)} by version {__version__}*")
    out.append("")
    out.append("## Machine")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    for key, value in (("Machine", report.machine.describe() or "unknown"),
                       ("Distribution", report.distro or "-"),
                       ("Desktop", report.desktop or "-"),
                       ("Kernel", report.kernel or "-"),
                       ("Processor", report.cpu_model or "-"),
                       ("Memory", f"{report.mem_total_mb} MB"),
                       ("System disk", report.root_disk or "-"),
                       ("Scan type", "deep" if report.deep else "quick")):
        out.append(f"| {key} | {value} |")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---|")
    for sev in SEVERITY_ORDER:
        out.append(f"| {sev.upper()} | {counts.get(sev, 0)} |")
    out.append("")

    findings = report.sorted_findings()
    out.append("## Findings")
    out.append("")
    for f in findings:
        out.append(f"### [{f.severity.value.upper()}] {f.title}")
        out.append("")
        out.append(f"*Category:* {CATEGORY_LABELS.get(f.category.value, f.category.value)} "
                   f"| *confidence:* {f.confidence.value} | *id:* `{f.id}`")
        out.append("")
        out.append(f.summary)
        out.append("")
        if f.root_cause:
            out.append(f"**Root cause:** {f.root_cause}")
            out.append("")
        if f.recommendations:
            out.append("**What to do:**")
            out.append("")
            for rec in f.recommendations:
                out.append(f"- {rec}")
            out.append("")
        if f.evidence:
            out.append("<details><summary>Evidence</summary>")
            out.append("")
            for ev in f.evidence:
                out.append(f"- **{ev.source}**: {ev.detail}")
                if ev.command:
                    out.append(f"  - `$ {ev.command}`")
            out.append("")
            out.append("</details>")
            out.append("")

    if repairs:
        out.append("## Repairs applied")
        out.append("")
        out.append("| Repair | Result | Before | After |")
        out.append("|---|---|---|---|")
        for r in repairs:
            out.append(f"| {r.title} | {r.state} | {r.verify_before[:60]} | {r.verify_after[:60]} |")
        out.append("")

    degraded = [r for r in report.results if r.state != "ok"]
    if degraded:
        out.append("## Checks that could not complete")
        out.append("")
        for r in degraded:
            out.append(f"- **{r.title}** ({r.state})"
                       + (f": {r.notes}" if r.notes else ""))
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Plain text
# --------------------------------------------------------------------------

_BAR = "=" * 78


def render_text(report: ScanReport, repairs: Sequence[RepairResult] = (),
                width: int = 78) -> str:
    counts = report.counts()
    out: List[str] = []
    out.append(_BAR)
    out.append(f"{APP_NAME} {__version__} - SYSTEM DIAGNOSTIC REPORT".center(width))
    out.append(_BAR)
    out.append(f"Machine     : {report.machine.describe() or 'unknown'}")
    out.append(f"Distribution: {report.distro or '-'}")
    out.append(f"Desktop     : {report.desktop or '-'}")
    out.append(f"Kernel      : {report.kernel or '-'}")
    out.append(f"Processor   : {report.cpu_model or '-'} ({report.cpu_cores} cores)")
    out.append(f"Memory      : {report.mem_total_mb} MB")
    out.append(f"System disk : {report.root_disk or '-'}")
    out.append(f"Scan        : {'deep' if report.deep else 'quick'} "
               f"({_duration(report)}), generated {_ts(report.finished or report.started)}")
    out.append("")
    out.append("SUMMARY: " + "  ".join(f"{s.upper()}={counts.get(s, 0)}"
                                       for s in SEVERITY_ORDER))
    out.append(_BAR)

    findings = report.sorted_findings()
    for f in findings:
        out.append("")
        out.append(f"[{f.severity.value.upper():8s}] {f.title}")
        out.append(f"           category: {CATEGORY_LABELS.get(f.category.value, f.category.value)}"
                   f" | confidence: {f.confidence.value}")
        for line in _wrap(f.summary, width - 11):
            out.append("           " + line)
        if f.root_cause:
            out.append("           ROOT CAUSE:")
            for line in _wrap(f.root_cause, width - 15):
                out.append("             " + line)
        for rec in f.recommendations:
            out.append(f"           -> {rec}")
        if f.repair_ids:
            out.append(f"           automatic repair: {', '.join(f.repair_ids)}")
        for ev in f.evidence:
            out.append(f"           evidence: {ev.source}: {ev.detail}")
            if ev.command:
                out.append(f"                     $ {ev.command}")

    if repairs:
        out.append("")
        out.append(_BAR)
        out.append("REPAIRS APPLIED")
        out.append(_BAR)
        for r in repairs:
            out.append(f"  [{r.state.upper()}] {r.title}")
            if r.verify_before:
                out.append(f"      before: {r.verify_before}")
            if r.verify_after:
                out.append(f"      after : {r.verify_after}")
            if r.backups:
                out.append(f"      backup: {r.backups[-1]}")

    degraded = [r for r in report.results if r.state != "ok"]
    if degraded:
        out.append("")
        out.append(_BAR)
        out.append("CHECKS THAT COULD NOT COMPLETE")
        out.append(_BAR)
        for r in degraded:
            out.append(f"  {r.title} ({r.state})"
                       + (f": {r.notes}" if r.notes else ""))
    out.append("")
    return "\n".join(out)


def _wrap(text: str, width: int) -> List[str]:
    import textwrap
    return textwrap.wrap(text, width=max(30, width)) or [""]


# --------------------------------------------------------------------------
# JSON / dispatch
# --------------------------------------------------------------------------


def render_json(report: ScanReport, repairs: Sequence[RepairResult] = ()) -> str:
    payload = report.to_dict()
    payload["generator"] = {"name": APP_NAME, "version": __version__}
    payload["repairs"] = [r.to_dict() for r in repairs]
    return json.dumps(payload, indent=2, default=str)


FORMATS = {
    "html": (render_html, ".html"),
    "markdown": (render_markdown, ".md"),
    "md": (render_markdown, ".md"),
    "text": (render_text, ".txt"),
    "txt": (render_text, ".txt"),
    "json": (render_json, ".json"),
}


def write_report(report: ScanReport, path: str, fmt: Optional[str] = None,
                 repairs: Sequence[RepairResult] = ()) -> str:
    """Write a report, choosing the format from the filename extension."""
    if fmt is None:
        ext = os.path.splitext(path)[1].lower()
        fmt = {".html": "html", ".htm": "html", ".md": "markdown",
               ".txt": "text", ".json": "json"}.get(ext, "html")
    if fmt not in FORMATS:
        raise ValueError(f"unknown report format: {fmt}")
    renderer, default_ext = FORMATS[fmt]
    if not os.path.splitext(path)[1]:
        path += default_ext
    content = renderer(report, repairs)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path
