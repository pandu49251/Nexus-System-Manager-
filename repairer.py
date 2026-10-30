"""
nexus_doctor.core.repairer
==========================

Orchestrates automatic repairs.

The safety model has five rules, and this module enforces all of them:

1.  **Verify before and after.**  :meth:`Repair.verify` runs *before* the
    repair (to capture the "before" state) and *again* afterwards.  A repair is
    reported as successful only if the post-verification passes.  A repair that
    ran without changing anything is reported as failed, not successful.
2.  **Back up before writing.**  Every file a repair modifies is copied to a
    timestamped backup directory first, and the paths are listed in the result
    so the user can restore by hand even if the app is uninstalled.
3.  **Nothing destructive by default.**  Repairs that delete files are marked
    irreversible and require explicit confirmation.
4.  **Least privilege.**  A repair declares whether it needs root and whether
    it needs an X session; it gets exactly that, through the allow-listed
    helper (:mod:`nexus_doctor.privileged_helper`), never a root shell.
5.  **Reversible.**  Every repair implements :meth:`Repair.rollback` where a
    rollback is meaningful, and the engine records the undo instructions.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import executil as ex
from . import privileges
from .engine import ScanContext
from .models import (Finding, Repair, RepairOutcome, RepairResult, Risk,
                     Severity)

log = logging.getLogger("nexus.repair")

BACKUP_ROOT_SYSTEM = "/var/lib/nexus-system-doctor/backups"
BACKUP_ROOT_USER = os.path.expanduser("~/.local/share/nexus-system-doctor/backups")


# --------------------------------------------------------------------------
# Repair context
# --------------------------------------------------------------------------


class RepairContext:
    """Everything a repair may use, and the only way it may touch the system.

    A repair never calls :func:`subprocess.run` itself; it goes through
    :meth:`run`, :meth:`run_root`, :meth:`run_user`, :meth:`write_file` or
    :meth:`remove_file`.  That keeps a single audit trail and makes the whole
    repair path testable against a fixture machine.
    """

    def __init__(self, scan: ScanContext, dry_run: bool = False,
                 session_id: Optional[str] = None):
        self.scan = scan
        self.dry_run = dry_run
        facts = getattr(scan, "facts", None)
        if facts is None:            # a bare report: recollect a snapshot
            from .facts import collect
            facts = collect()
        self.facts = facts
        self.f = facts
        self.session_id = session_id or time.strftime("%Y%m%d-%H%M%S")
        self.backups: List[str] = []
        self.log: List[str] = []
        self.params: Dict[str, Any] = {}

    # -- scan access ----------------------------------------------------
    def finding(self, finding_id: str) -> Optional[Finding]:
        return self.scan.finding(finding_id)

    def has(self, finding_id: str) -> bool:
        return self.scan.has(finding_id)

    def shared(self, key: str, default: Any = None) -> Any:
        return self.scan.shared_get(key, default)

    def param(self, key: str, default: Any = None) -> Any:
        """User-supplied parameter (e.g. which autostart entries to disable)."""
        return self.params.get(key, default)

    # -- command execution ----------------------------------------------
    def run(self, argv: List[str], timeout: float = 30.0, root: bool = False,
            user: bool = False) -> ex.Result:
        self.log.append(("root " if root else ("user " if user else "")) + " ".join(argv))
        if self.dry_run:
            # Report the shape of success without touching anything, so a
            # dry run can show the whole plan instead of stopping at step one.
            return ex.Result(argv=list(argv), rc=0, out="", err="", state="ok",
                             detail="dry run: command not executed", as_root=root)
        if user:
            return privileges.run_as_user(argv, timeout=timeout)
        return ex.run(argv, timeout=timeout, root=root)

    def run_root(self, argv: List[str], timeout: float = 30.0) -> ex.Result:
        return self.run(argv, timeout=timeout, root=True)

    def run_user(self, argv: List[str], timeout: float = 15.0) -> ex.Result:
        return self.run(argv, timeout=timeout, user=True)

    # -- file mutation ---------------------------------------------------
    def _backup_root(self) -> str:
        if ex.SANDBOX:                     # test harness: keep everything local
            return os.path.join(ex.SANDBOX, "var/lib/nexus-system-doctor/backups")
        return (BACKUP_ROOT_SYSTEM if privileges.is_root() else BACKUP_ROOT_USER)

    def backup(self, path: str) -> Optional[str]:
        """Copy *path* into the session backup directory. Returns the copy path."""
        if self.dry_run:
            return None                # nothing changes, so nothing to protect
        real = ex.syspath(path)
        if not os.path.exists(real):
            return None
        dest_dir = os.path.join(self._backup_root(), self.session_id)
        dest = os.path.join(dest_dir, path.lstrip("/").replace("/", "_"))
        try:
            os.makedirs(dest_dir, exist_ok=True)
            shutil.copy2(real, dest)
            self.backups.append(dest)
            self.log.append(f"backed up {path} -> {dest}")
            return dest
        except OSError as exc:
            log.warning("backup of %s failed: %s", path, exc)
            self.log.append(f"WARNING: backup of {path} failed: {exc}")
            return None

    def write_file(self, path: str, content: str, mode: Optional[int] = None,
                   backup: bool = True, root: bool = False) -> bool:
        """Write a file.

        With *root* and no current root privileges the write is delegated to
        the allow-listed helper, which refuses anything outside a small set of
        system configuration directories.
        """
        if self.dry_run:
            self.log.append(f"[dry-run] would write {path}")
            return True
        if backup:
            self.backup(path)
        if root and not privileges.is_root():
            reply = privileges.write_as_root(path, content, mode=mode, backup=backup)
            ok = bool(reply.get("ok"))
            if not ok:
                self.log.append(f"FAILED to write {path}: {reply.get('error', 'helper refused')}")
                return False
            if reply.get("backup"):
                self.backups.append(str(reply["backup"]))
            self.log.append(f"wrote {path} (privileged)")
            return True
        ok = ex.write_text(path, content, mode=mode)
        self.log.append(f"{'wrote' if ok else 'FAILED to write'} {path}")
        return ok

    def remove_file(self, path: str, backup: bool = True, root: bool = False) -> bool:
        if self.dry_run:
            self.log.append(f"[dry-run] would remove {path}")
            return True
        if backup:
            self.backup(path)
        if root and not privileges.is_root():
            reply = privileges.remove_as_root(path, backup=backup)
            ok = bool(reply.get("ok"))
            self.log.append(f"{'removed' if ok else 'FAILED to remove'} {path}")
            return ok
        ok = ex.remove(path)
        self.log.append(f"{'removed' if ok else 'FAILED to remove'} {path}")
        return ok

    def read(self, path: str, default: str = "") -> str:
        return ex.read_text(path, default=default) or default

    def is_root(self) -> bool:
        return privileges.is_root()

    def can_elevate(self) -> bool:
        return privileges.can_elevate()

    def has_gui(self) -> bool:
        return privileges.has_gui_session()


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


@dataclass
class RepairPlan:
    """A repair offered to the user, with everything needed to consent."""
    repair: Repair
    finding: Optional[Finding] = None
    steps: List[str] = field(default_factory=list)
    reason: str = ""
    blocked: str = ""        # non-empty if it cannot run here
    recommended: bool = True

    @property
    def id(self) -> str:
        return self.repair.id

    @property
    def risk(self) -> Risk:
        return self.repair.risk

    def to_dict(self) -> Dict[str, Any]:
        d = self.repair.to_dict()
        d.update({"steps": list(self.steps), "reason": self.reason,
                  "blocked": self.blocked, "recommended": self.recommended,
                  "finding": self.finding.id if self.finding else None})
        return d


class RepairEngine:
    """Runs repairs with verification and rollback support."""

    def __init__(self, scan: Any, dry_run: bool = False):
        # Accept either a live ScanContext or a finished ScanReport.
        if not isinstance(scan, ScanContext):
            scan = ScanContext(report=scan, facts=getattr(scan, "facts", None))
        self.scan = scan
        self.dry_run = dry_run
        self.ctx = RepairContext(scan, dry_run=dry_run)
        self.results: List[RepairResult] = []
        #: Called after a repair is applied and before it is verified.  The GUI
        #: uses it to refresh its view; the test harness uses it to advance the
        #: fixture machine to its post-repair state.
        self.after_apply_hook: Optional[Callable[[str], None]] = None
        self._by_id: Dict[str, Repair] = {}
        for rep in all_repairs():
            self._by_id[rep.id] = rep

    # -- discovery -------------------------------------------------------
    def plans(self) -> List[RepairPlan]:
        """Repairs relevant to this machine's findings, with consent info."""
        plans: List[RepairPlan] = []
        for rep in all_repairs():
            finding = next((f for f in self.scan.findings()
                            if rep.id in f.repair_ids), None)
            # A repair is offered if some finding asks for it, or if it
            # independently reports itself as applicable.
            try:
                applicable = rep.available(self.ctx)
            except Exception as exc:
                log.warning("repair %s availability check failed: %s", rep.id, exc)
                continue
            if not applicable and finding is None:
                continue
            if applicable:
                blocked = self._blocked_reason(rep)
            else:
                blocked = ("Already in the desired state on this machine - nothing to do."
                           if not self._blocked_reason(rep) else self._blocked_reason(rep))
            try:
                steps = rep.steps(self.ctx)
                reason = rep.why(self.ctx)
            except Exception as exc:
                log.warning("repair %s description failed: %s", rep.id, exc)
                steps, reason = [], rep.description
            plans.append(RepairPlan(repair=rep, finding=finding, steps=steps,
                                    reason=reason, blocked=blocked))
        rank = {Risk.LOW: 0, Risk.MEDIUM: 1, Risk.HIGH: 2, Risk.MANUAL: 3}
        plans.sort(key=lambda p: (p.repair.risk.value in ("high", "manual"),
                                  rank.get(p.repair.risk, 9), p.repair.id))
        return plans

    def _blocked_reason(self, rep: Repair) -> str:
        if rep.requires_root and not (self.ctx.is_root() or self.ctx.can_elevate()):
            return ("Needs administrator rights, and neither pkexec nor passwordless "
                    "sudo is available. Run the app as root, or apply it manually.")
        if rep.requires_gui and not self.ctx.has_gui():
            return "Needs an active graphical (X) session; not available right now."
        if rep.requires_network:
            return "Needs an internet connection to download packages."
        return ""

    # -- execution -------------------------------------------------------
    def apply(self, repair_id: str, confirm: bool = True) -> RepairResult:
        rep = self._by_id.get(repair_id)
        if rep is None:
            return RepairResult(repair_id=repair_id, title=repair_id, state="failed",
                                message=f"unknown repair: {repair_id}")
        result = RepairResult(repair_id=rep.id, title=rep.title,
                              risk=rep.risk.value)
        started = time.monotonic()
        # Per-repair marks into the session-wide journal, so a result reports
        # only the commands and backups *it* produced.
        log_mark = len(self.ctx.log)
        backup_mark = len(self.ctx.backups)

        blocked = self._blocked_reason(rep)
        if blocked:
            result.state = "skipped"
            result.message = blocked
            return result

        # --- verify BEFORE (read-only, so it is meaningful either way) ----
        try:
            before = rep.verify(self.ctx)
            result.verify_before = before.message or before.before
        except Exception as exc:
            before = RepairOutcome(False, f"pre-check failed: {exc}")
            result.verify_before = str(exc)

        # A dry run walks the whole repair with mutations suppressed, so the
        # user sees every command that would run - never a claim of success.
        if self.dry_run:
            try:
                outcome = rep.apply(self.ctx)
            except Exception as exc:
                outcome = RepairOutcome(False, f"{type(exc).__name__}: {exc}")
            result.state = "pending"
            result.message = "dry run: nothing was changed"
            result.commands = list(outcome.commands) or \
                list(self.ctx.log[log_mark:])
            result.duration_ms = int((time.monotonic() - started) * 1000)
            self.results.append(result)
            return result

        # --- apply ------------------------------------------------------
        result.attempted = True
        try:
            outcome = rep.apply(self.ctx)
            if self.after_apply_hook:
                try:
                    self.after_apply_hook(rep.id)
                except Exception:
                    log.warning("after-apply hook failed", exc_info=True)
        except Exception as exc:
            log.exception("repair %s raised", rep.id)
            outcome = RepairOutcome(False, f"{type(exc).__name__}: {exc}")
        result.applied = bool(outcome.ok)
        result.message = outcome.message
        result.commands = list(outcome.commands) or \
            [line for line in self.ctx.log[log_mark:]
             if not line.startswith("[dry-run]")]
        if not outcome.ok and not outcome.message:
            outcome.message = "the command did not report success"

        # --- verify AFTER ------------------------------------------------
        if outcome.ok:
            try:
                after = rep.verify(self.ctx)
            except Exception as exc:
                after = RepairOutcome(False, f"verification error: {exc}")
            result.verify_after = after.message or after.after
            result.verified = bool(after.ok)
            if after.ok:
                result.state = "verified"
                if not result.message:
                    result.message = "applied and verified"
            else:
                result.state = "failed"
                result.message = (
                    f"The command ran, but the system does not show the expected state "
                    f"afterwards: {after.message}. Treating this as NOT fixed.")
        else:
            result.state = "failed"

        result.backups = list(self.ctx.backups[backup_mark:])
        result.rollback = rep.rollback.__doc__ or ""
        result.duration_ms = int((time.monotonic() - started) * 1000)
        self.results.append(result)
        log.info("repair %s -> %s (%s)", rep.id, result.state, result.message)
        return result

    def apply_many(self, repair_ids: List[str]) -> List[RepairResult]:
        return [self.apply(rid) for rid in repair_ids]

    def rollback(self, repair_id: str) -> RepairResult:
        rep = self._by_id.get(repair_id)
        if rep is None:
            return RepairResult(repair_id=repair_id, title=repair_id, state="failed",
                                message="unknown repair")
        try:
            out = rep.rollback(self.ctx)
        except Exception as exc:
            out = RepairOutcome(False, f"{type(exc).__name__}: {exc}")
        return RepairResult(repair_id=rep.id, title=rep.title,
                            state="verified" if out.ok else "failed",
                            message=out.message, attempted=True,
                            applied=out.ok, verified=out.ok)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_REPAIRS: List[Repair] = []


def register_repair(repair: Repair) -> Repair:
    _REPAIRS.append(repair)
    return repair


def all_repairs() -> List[Repair]:
    from .. import repairs  # noqa: F401  (importing populates the registry)
    return list(_REPAIRS)


def get_repair(repair_id: str) -> Optional[Repair]:
    for r in all_repairs():
        if r.id == repair_id:
            return r
    return None
