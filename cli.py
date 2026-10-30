"""
nexus_doctor.ui.cli
===================

Command-line interface.

The CLI exists for three reasons that a GUI cannot cover:

* running on a machine with no working desktop (exactly the situation where
  this tool is most useful);
* running over SSH, or from a live USB while repairing an installed system;
* scripting and reproducibility: ``--json`` output can be diffed before and
  after a change to prove what actually improved.

Examples
--------
    nexus-doctor --scan                  # quick read-only scan, text report
    nexus-doctor --scan --deep --report ~/nexus-report.html
    nexus-doctor --scan --json before.json
    sudo nexus-doctor --scan --deep --repair --safe
    nexus-doctor --list-repairs
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import List, Optional

from ..core import privileges, report as reporting
from ..core.engine import Engine, load_checks
from ..core.models import Severity
from ..core.repairer import RepairEngine
from ..version import APP_NAME, __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nexus-doctor",
        description=f"{APP_NAME} {__version__} - diagnose and repair Linux desktop problems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")

    action = p.add_mutually_exclusive_group()
    action.add_argument("--scan", action="store_true",
                        help="run a read-only diagnostic scan (default action)")
    action.add_argument("--list-checks", action="store_true",
                        help="list available diagnostic checks")
    action.add_argument("--list-repairs", action="store_true",
                        help="list available repairs and whether they apply here")

    p.add_argument("--deep", action="store_true",
                   help="include deeper (slower) checks such as a disk speed measurement")
    p.add_argument("--only", metavar="ID[,ID]", help="run only these check ids")
    p.add_argument("--skip", metavar="ID[,ID]", help="skip these check ids")
    p.add_argument("--json", metavar="FILE", help="write machine-readable JSON here ('-' for stdout)")
    p.add_argument("--report", metavar="FILE",
                   help="write a formatted report (format from the extension: "
                        ".html .md .txt .json)")
    p.add_argument("--text", action="store_true", help="print the plain-text report to stdout")

    # repairs
    p.add_argument("--repair", nargs="?", const="__all__", metavar="ID[,ID]",
                   help="apply repairs: all applicable, or a comma-separated list")
    p.add_argument("--safe", action="store_true",
                   help="with --repair, allow only low-risk, fully reversible repairs")
    p.add_argument("--dry-run", action="store_true",
                   help="show what a repair would do without changing anything")
    p.add_argument("--rollback", metavar="ID[,ID]", help="undo previously applied repairs")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="increase logging (-v info, -vv debug)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    return p


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

_COLOURS = {"critical": "\033[1;31m", "high": "\033[0;31m", "medium": "\033[0;33m",
            "low": "\033[0;36m", "info": "\033[0;37m", "ok": "\033[0;32m"}
_RESET = "\033[0m"


def _c(text: str, colour: str, enabled: bool = True) -> str:
    return f"{_COLOURS.get(colour, '')}{text}{_RESET}" if enabled else text


def print_report(report, colour: bool = True) -> None:
    counts = report.counts()
    print()
    print(f"{APP_NAME} {__version__} - diagnostic report")
    print("=" * 72)
    print(f"  Machine      : {report.machine.describe() or 'unknown'}")
    if report.machine.serial:
        print(f"  Serial       : {report.machine.serial}")
    print(f"  Distribution : {report.distro or 'unknown'}")
    print(f"  Desktop      : {report.desktop or 'unknown'}")
    print(f"  Kernel       : {report.kernel}")
    print(f"  Processor    : {report.cpu_model or 'unknown'} "
          f"({report.cpu_cores} core(s))")
    print(f"  Memory       : {report.mem_total_mb} MB")
    print(f"  System disk  : {report.root_disk or 'unknown'}")
    print(f"  Scan         : {'deep' if report.deep else 'quick'} in "
          f"{report.finished - report.started:.1f}s as {report.run_as}"
          f"{' (root)' if privileges.is_root() else ''}")
    print("  " + "-" * 68)
    print("  " + "   ".join(f"{s.upper()}={counts.get(s, 0)}" for s in
                            ("critical", "high", "medium", "low", "info", "ok")))
    print("=" * 72)

    findings = sorted(report.findings, key=lambda f: (f.severity.rank, f.id))
    for f in findings:
        print()
        print(f"  {_c(f'[{f.severity.value.upper():8s}]', f.severity.value, colour)} {f.title}")
        print(f"      category  : {f.category.value} | confidence: {f.confidence.value}")
        for line in reporting._wrap(f.summary, 62):
            print(f"      {line}")
        if f.root_cause:
            print("      root cause:")
            for line in reporting._wrap(f.root_cause, 58):
                print(f"        {line}")
        for rec in f.recommendations:
            print(f"      ->  {rec}")
        if f.repair_ids:
            print(f"      repair available: {', '.join(f.repair_ids)}")
        for ev in f.evidence:
            print(f"      evidence: {ev.source}: {ev.detail}")
            if ev.command:
                print(f"                 $ {ev.command}")
    degraded = [r for r in report.results if r.state != "ok"]
    if degraded:
        print()
        print("  Checks that could not complete:")
        for r in degraded:
            print(f"    - {r.title} ({r.state})"
                  + (f": {r.notes}" if r.notes else ""))
    print()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")

    load_checks()
    colour = not args.no_color and sys.stdout.isatty()

    # ---------------------------------------------------------- listings
    if args.list_checks:
        from ..core.engine import CHECKS
        print(f"{'CHECK ID':20s} {'DEEP':5s}  TITLE")
        for c in sorted(CHECKS, key=lambda c: c.id):
            print(f"{c.id:20s} {'yes' if c.deep else 'no':5s}  {c.title}")
        return 0

    # ------------------------------------------------------------- scan
    only = args.only.split(",") if args.only else None
    skip = args.skip.split(",") if args.skip else None
    started = time.time()
    engine = Engine(deep=args.deep, only=only, skip=skip)

    def progress(cid, title, done, total):
        bar = "#" * int(20 * done / max(1, total))
        sys.stderr.write(f"\r  scanning [{bar:<20s}] {done}/{total} {title[:34]:<34s}")
        sys.stderr.flush()

    if not (args.list_repairs or args.json or args.report or args.text or args.repair):
        args.text = True

    report = engine.run(progress=progress if sys.stderr.isatty() else None)
    if sys.stderr.isatty():
        sys.stderr.write("\r" + " " * 78 + "\r")
        sys.stderr.flush()

    repairs: List = []
    repair_engine = RepairEngine(report, dry_run=args.dry_run)

    # ----------------------------------------------------------- repairs
    if args.list_repairs:
        plans = repair_engine.plans()
        print(f"{'REPAIR ID':30s} {'RISK':8s} {'ROOT':5s}  STATUS / REASON")
        for p in plans:
            flag = "root" if p.repair.requires_root else "    "
            print(f"{p.id:30s} {p.risk.value:8s} {flag:5s}  {p.blocked or p.reason}")
        if not plans:
            print("  (no repairs are applicable to this machine)")
        return 0

    if args.repair:
        wanted = None if args.repair == "__all__" else \
            [x.strip() for x in args.repair.split(",") if x.strip()]
        plans = [p for p in repair_engine.plans()
                 if (wanted is None or p.id in wanted) and not p.blocked]
        if args.safe:
            plans = [p for p in plans if p.repair.risk.value == "low"]
        if args.dry_run:
            print("\nDRY RUN - nothing will be changed\n")
        if not plans:
            print("No applicable repairs to apply.")
        else:
            print("\nThe following repairs will be applied:")
            for p in plans:
                print(f"  [{p.risk.value.upper():6s}] {p.repair.title}")
                for step in p.steps:
                    print(f"            - {step}")
            if not args.yes and not args.dry_run:
                answer = input("\nProceed? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    print("Aborted; nothing was changed.")
                    return 1
            print()
            for p in plans:
                result = repair_engine.apply(p.id, confirm=False)
                repairs.append(result)
                mark = {"verified": "OK  ", "pending": "DRY "}.get(result.state, "FAIL")
                print(f"  [{mark}] {result.title}")
                if result.state == "pending":
                    print("         planned, not applied: no change was made")
                else:
                    if result.verify_before:
                        print(f"         before: {result.verify_before}")
                    if result.verify_after:
                        print(f"         after : {result.verify_after}")
                if result.state not in ("verified", "pending"):
                    print(f"         {result.message}")
                elif result.commands and result.state == "pending":
                    for cmd in result.commands:
                        print(f"         would run: {cmd}")
                if result.backups:
                    print(f"         backup: {result.backups[-1]}")
            print()

    if args.rollback:
        for rid in [x.strip() for x in args.rollback.split(",") if x.strip()]:
            result = repair_engine.rollback(rid)
            print(f"  [{result.state.upper()}] {rid}: {result.message}")

    # --------------------------------------------------------- reporting
    if args.text:
        print_report(report, colour=colour)
    if args.json:
        data = reporting.render_json(report, repairs)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
            print(f"JSON written to {args.json}")
    if args.report:
        path = reporting.write_report(report, args.report, repairs=repairs)
        print(f"Report written to {path}")

    if not any((args.text, args.json, args.report, args.repair, args.rollback)):
        print_report(report, colour=colour)

    # Exit code encodes the worst finding, so scripts can react to it.
    counts = report.counts()
    if counts.get("critical"):
        return 2
    if counts.get("high"):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
