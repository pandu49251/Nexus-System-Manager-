"""
nexus_doctor.checks.common
==========================

Helpers shared by the check modules: process table, journal / kernel log
access, unit conversion, and report-building conveniences.

All filesystem and command access goes through :mod:`nexus_doctor.core.executil`
so the scan stays redirectable (for tests) and auditable (in the log).
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..core import executil as ex
from ..core.models import (Category, CheckResult, Confidence, Evidence,
                           Finding, Severity)

log = logging.getLogger("nexus.checks")


# --------------------------------------------------------------------------
# Process table (pure /proc parsing - no ps, no shell)
# --------------------------------------------------------------------------


@dataclass
class Proc:
    pid: int
    ppid: int = 0
    comm: str = ""
    cmdline: str = ""
    state: str = ""
    rss_kb: int = 0
    utime: int = 0
    stime: int = 0

    @property
    def name(self) -> str:
        if self.cmdline:
            base = os.path.basename(self.cmdline.split()[0])
            return base
        return self.comm

    @property
    def rss_mb(self) -> int:
        return self.rss_kb // 1024


def processes(limit: int = 400) -> List[Proc]:
    """Snapshot of the process table.

    Uses ``/proc/<pid>/stat`` (RSS in pages via statm) and ``cmdline``.
    Deliberately avoids ``ps``: fewer dependencies, faster on a slow disk,
    and it works identically on every distribution.
    """
    out: List[Proc] = []
    pids = [p for p in ex.listdir("/proc") if p.isdigit()]
    for pid in pids[:limit]:
        stat = ex.read_text(f"/proc/{pid}/stat")
        if not stat:
            continue
        try:
            rparen = stat.rindex(")")
            fields = stat[rparen + 2:].split()
            comm = stat[stat.index("(") + 1:rparen]
            state = fields[0]
            ppid = int(fields[1])
            utime = int(fields[11])
            stime = int(fields[12])
        except (ValueError, IndexError):
            continue
        statm = ex.read_text(f"/proc/{pid}/statm") or ""
        rss_pages = 0
        try:
            rss_pages = int(statm.split()[1])
        except (ValueError, IndexError):
            pass
        raw = ex.read_bytes(f"/proc/{pid}/cmdline", 2048)
        cmdline = raw.replace(b"\0", b" ").decode("utf-8", "replace").strip() if raw else ""
        out.append(Proc(pid=int(pid), ppid=ppid, comm=comm, cmdline=cmdline,
                        state=state, rss_kb=rss_pages * (os.sysconf("SC_PAGE_SIZE") // 1024),
                        utime=utime, stime=stime))
    return out


def top_memory_procs(procs: Sequence[Proc], n: int = 6, skip_self: bool = True) -> List[Proc]:
    me = os.getpid()
    filtered = [p for p in procs if not (skip_self and p.pid == me)]
    filtered.sort(key=lambda p: p.rss_kb, reverse=True)
    return filtered[:n]


def cpu_usage_sample(procs: Sequence[Proc], interval: float = 0.6,
                     n: int = 6) -> List[Tuple[Proc, float]]:
    """Measure per-process CPU usage over *interval* seconds.

    Returns a list of (proc, percent-of-one-core) sorted descending.  This is a
    real measurement, not an average-since-boot figure, so it reflects what is
    burning CPU *right now*.
    """
    before = {p.pid: (p.utime, p.stime) for p in procs}
    time.sleep(interval)
    after: Dict[int, Tuple[int, int]] = {}
    for p in processes(limit=400):
        after[p.pid] = (p.utime, p.stime)
    ticks = os.sysconf("SC_CLK_TCK")
    results: List[Tuple[Proc, float]] = []
    for p in procs:
        b = before.get(p.pid)
        a = after.get(p.pid)
        if not b or not a:
            continue
        delta = (a[0] - b[0]) + (a[1] - b[1])
        if delta <= 0:
            continue
        pct = (delta / ticks) / interval * 100.0
        results.append((p, pct))
    results.sort(key=lambda t: t[1], reverse=True)
    return results[:n]


def find_procs(procs: Sequence[Proc], patterns: Iterable[str]) -> List[Proc]:
    """Processes whose cmdline or comm matches any regex in *patterns*."""
    regs = [re.compile(p, re.I) for p in patterns]
    out: List[Proc] = []
    for p in procs:
        hay = f"{p.cmdline} {p.comm}"
        for r in regs:
            if r.search(hay):
                out.append(p)
                break
    return out


# --------------------------------------------------------------------------
# Log access
# --------------------------------------------------------------------------

_JOURNAL_CACHE: Optional[List[str]] = None


def kernel_messages(limit: int = 400) -> List[str]:
    """Kernel ring buffer, best effort, several fallbacks.

    Order: ``journalctl -k -b`` (no root on Mint, user is in 'adm'), then
    ``dmesg`` (may be restricted by kernel.dmesg_restrict), then
    ``/var/log/syslog``.  Returns an empty list if nothing is readable -- in
    which case checks report reduced confidence rather than inventing data.
    """
    r = ex.run(["journalctl", "-k", "-b", "--no-pager", "-o", "cat", "-n", str(limit)],
               timeout=12)
    if r.ok and r.out.strip():
        return r.lines
    r = ex.run(["dmesg", "-T"], timeout=12)
    if r.ok and r.out.strip():
        return r.lines
    r = ex.run(["dmesg"], timeout=12)
    if r.ok and r.out.strip():
        return r.lines
    syslog = ex.read_text("/var/log/syslog")
    if syslog:
        return syslog.splitlines()[-limit:]
    return []


def journal_messages(priority: int = 3, limit: int = 400, unit: Optional[str] = None) -> List[str]:
    """Recent system log messages at or above *priority* (0=emerg .. 3=err)."""
    argv = ["journalctl", "-p", str(priority), "-b", "--no-pager", "-o", "cat",
            "-n", str(limit)]
    if unit:
        argv.extend(["-u", unit])
    r = ex.run(argv, timeout=15)
    if r.ok and r.out.strip():
        return r.lines
    # Fallback: syslog (Mint still ships rsyslog by default).
    syslog = ex.read_text("/var/log/syslog")
    if syslog:
        level_names = ("emerg", "alert", "crit", "err", "error")
        return [l for l in syslog.splitlines()[-limit * 4:]
                if any(n in l.lower() for n in level_names)][-limit:]
    return []


def match_lines(lines: Sequence[str], patterns: Iterable[str],
                limit: int = 5) -> List[Tuple[str, str]]:
    """Return (pattern, line) for the first *limit* matches of any pattern."""
    regs = [(p, re.compile(p, re.I)) for p in patterns]
    out: List[Tuple[str, str]] = []
    for line in lines:
        for raw, reg in regs:
            if reg.search(line):
                out.append((raw, line.strip()))
                break
        if len(out) >= limit:
            break
    return out


def count_matches(lines: Sequence[str], patterns: Iterable[str]) -> Dict[str, int]:
    regs = [(p, re.compile(p, re.I)) for p in patterns]
    counts: Dict[str, int] = {p: 0 for p, _ in regs}
    for line in lines:
        for raw, reg in regs:
            if reg.search(line):
                counts[raw] += 1
    return counts


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0 or unit == "TB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024.0
    return f"{num:.1f} TB"


def pct(part: float, whole: float, digits: int = 0) -> float:
    if whole <= 0:
        return 0.0
    return round(part * 100.0 / whole, digits)


def uptime_text(seconds: float) -> str:
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    m = int((seconds % 3600) // 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# --------------------------------------------------------------------------
# Result assembly
# --------------------------------------------------------------------------


def result(check_id: str, title: str, category: Category,
           findings: List[Finding], state: str = "ok", notes: str = "",
           facts: Optional[Dict] = None) -> CheckResult:
    return CheckResult(check_id=check_id, title=title, category=category,
                       findings=findings, state=state, notes=notes,
                       facts=facts or {})


def degraded(check_id: str, title: str, category: Category, reason: str,
             how_to_fix: str = "") -> CheckResult:
    """A check that could not run -- reported honestly as INFO, not hidden."""
    f = Finding(
        id=f"{check_id}.incomplete",
        title=f"{title} - data incomplete",
        category=category,
        severity=Severity.INFO,
        summary=f"This check could not collect complete data: {reason}",
        root_cause=reason,
        confidence=Confidence.DIRECT,
        needs_root="root" in reason.lower() or "admin" in reason.lower(),
        manual=True,
        recommendations=[how_to_fix] if how_to_fix else [],
        evidence=[Evidence(source="Nexus System Doctor", detail=reason)],
    )
    return result(check_id, title, category, [f], state="degraded", notes=reason)


def ok_finding(check_id: str, title: str, category: Category,
               what: str, evidence: List[Evidence]) -> Finding:
    return Finding(id=f"{check_id}.ok", title=title, category=category,
                   severity=Severity.OK, summary=what, evidence=evidence,
                   confidence=Confidence.MEASURED)
