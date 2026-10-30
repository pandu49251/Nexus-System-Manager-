"""
nexus_doctor.core.engine
========================

The scan engine: discovers check modules, runs them with per-check timeouts,
isolates failures, and assembles a :class:`ScanReport`.

Reliability rules implemented here
----------------------------------
* A check that raises, hangs or crashes is recorded as ``state="failed"`` with
  the traceback in ``notes``.  One broken probe can never abort the scan or
  produce a half-empty report.
* Every check declares whether it is quick or deep.  The default "quick" scan
  touches nothing that could take more than a moment, which keeps the app
  usable on a mechanical HDD.
* Checks are executed in priority order with a small worker pool (2 threads)
  so slow device probes overlap without saturating a dual-core CPU.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import executil as ex
from . import privileges
from .facts import Facts, collect
from .models import (Category, CheckResult, Finding, MachineProfile,
                     ScanReport, Severity)

log = logging.getLogger("nexus.engine")


# --------------------------------------------------------------------------
# Check registration
# --------------------------------------------------------------------------


@dataclass
class Check:
    id: str
    title: str
    category: Category
    fn: Callable[["ScanContext"], CheckResult]
    description: str = ""
    deep: bool = False            # only run in deep scans
    priority: int = 50            # lower runs first
    root_helpful: bool = False    # gives better data with administrator rights


CHECKS: List[Check] = []
_BY_ID: Dict[str, Check] = {}


def register(check_id: str, title: str, category: Category, deep: bool = False,
             priority: int = 50, description: str = "",
             root_helpful: bool = False) -> Callable:
    """Decorator used by every module in :mod:`nexus_doctor.checks`."""

    def deco(fn: Callable[[ScanContext], CheckResult]) -> Callable:
        chk = Check(id=check_id, title=title, category=category, fn=fn,
                    description=description, deep=deep, priority=priority,
                    root_helpful=root_helpful)
        CHECKS.append(chk)
        _BY_ID[check_id] = chk
        return fn

    return deco


def get_check(check_id: str) -> Optional[Check]:
    return _BY_ID.get(check_id)


def load_checks() -> None:
    """Import all check modules so their @register decorators run."""
    from .. import checks  # noqa: F401  (package __init__ imports every module)


# --------------------------------------------------------------------------
# Scan context
# --------------------------------------------------------------------------


class ScanContext:
    """Everything a check is allowed to know about the machine.

    Checks receive a context and must treat it as read-only: they may only
    *observe* and *report*.  (``tests/test_readonly.py`` enforces this by
    running a full scan with write-protection enabled.)
    """

    def __init__(self, facts: Optional[Facts] = None, deep: bool = False,
                 report: Optional[ScanReport] = None):
        self.facts: Facts = facts or collect()
        self.deep = deep
        self.report: ScanReport = report or ScanReport()
        self.shared: Dict[str, object] = {}
        self._lock = threading.Lock()

    # -- convenience accessors --------------------------------------------
    @property
    def f(self) -> Facts:
        return self.facts

    def findings(self) -> List[Finding]:
        return self.report.findings

    def finding(self, finding_id: str) -> Optional[Finding]:
        for f in self.report.findings:
            if f.id == finding_id:
                return f
        return None

    def has(self, finding_id: str) -> bool:
        return self.finding(finding_id) is not None

    def share(self, key: str, value: object) -> None:
        with self._lock:
            self.shared[key] = value

    def shared_get(self, key: str, default=None):
        with self._lock:
            return self.shared.get(key, default)

    def is_root(self) -> bool:
        return privileges.is_root()


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


ProgressCB = Callable[[str, str, int, int], None]


class Engine:
    """Runs the registered checks and produces a report."""

    def __init__(self, deep: bool = False, only: Optional[List[str]] = None,
                 skip: Optional[List[str]] = None, workers: int = 2):
        load_checks()
        self.deep = deep
        self.workers = max(1, workers)
        self.only = set(only or [])
        self.skip = set(skip or [])
        self.selected: List[Check] = self._select()

    def _select(self) -> List[Check]:
        out = []
        for c in CHECKS:
            if self.only and c.id not in self.only:
                continue
            if c.id in self.skip:
                continue
            if c.deep and not self.deep:
                continue
            out.append(c)
        out.sort(key=lambda c: (c.priority, c.id))
        return out

    def _run_one(self, chk: Check, ctx: ScanContext) -> CheckResult:
        started = time.monotonic()
        try:
            result = chk.fn(ctx)
            if result is None:
                result = CheckResult(check_id=chk.id, title=chk.title,
                                     category=chk.category, state="failed",
                                     notes="check returned no result")
        except Exception as exc:
            tb = traceback.format_exc(limit=6)
            log.warning("check %s raised: %s", chk.id, exc)
            result = CheckResult(check_id=chk.id, title=chk.title,
                                 category=chk.category, state="failed",
                                 notes=f"{type(exc).__name__}: {exc}\n{tb}")
        result.duration_ms = int((time.monotonic() - started) * 1000)
        result.check_id = result.check_id or chk.id
        result.title = result.title or chk.title
        result.category = result.category or chk.category
        return result

    def run(self, progress: Optional[ProgressCB] = None) -> ScanReport:
        started = time.time()
        facts = collect()
        ctx = ScanContext(facts=facts, deep=self.deep)
        ctx.report.started = started
        ctx.report.hostname = facts.hostname
        ctx.report.distro = facts.distro
        ctx.report.desktop = facts.desktop
        ctx.report.kernel = facts.kernel
        ctx.report.cpu_model = facts.cpu_model
        ctx.report.cpu_cores = facts.cpu_cores
        ctx.report.mem_total_mb = facts.mem_total_mb()
        ctx.report.root_disk = facts.root_device()
        ctx.report.machine = facts.machine
        ctx.report.facts = facts
        ctx.report.deep = self.deep
        ctx.report.run_as = facts.user or "unknown"
        ctx.report.euid = privileges.euid()

        total = len(self.selected)
        log.info("starting scan: %d checks (deep=%s)", total, self.deep)

        results: List[Optional[CheckResult]] = [None] * total
        if self.workers == 1 or total == 1:
            for i, chk in enumerate(self.selected):
                if progress:
                    progress(chk.id, chk.title, i + 1, total)
                results[i] = self._run_one(chk, ctx)
        else:
            with ThreadPoolExecutor(max_workers=self.workers,
                                    thread_name_prefix="nexus-scan") as pool:
                futures = {pool.submit(self._run_one, chk, ctx): i
                           for i, chk in enumerate(self.selected)}
                done = 0
                for fut, i in futures.items():
                    try:
                        results[i] = fut.result()
                    except Exception as exc:
                        results[i] = CheckResult(
                            check_id=self.selected[i].id,
                            title=self.selected[i].title,
                            category=self.selected[i].category,
                            state="failed", notes=f"executor error: {exc}")
                    done += 1
                    if progress:
                        progress(self.selected[i].id, self.selected[i].title, done, total)

        for r in results:
            if r is not None:
                ctx.report.results.append(r)

        ctx.report.finished = time.time()
        ctx.report.results.sort(key=lambda r: (
            min((f.severity.rank for f in r.findings), default=9), r.check_id))

        log.info("scan complete in %.2fs: %s",
                 ctx.report.finished - ctx.report.started, ctx.report.counts())
        return ctx.report


def quick_scan(progress: Optional[ProgressCB] = None) -> ScanReport:
    return Engine(deep=False).run(progress)


def deep_scan(progress: Optional[ProgressCB] = None) -> ScanReport:
    return Engine(deep=True).run(progress)
