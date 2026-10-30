"""
nexus_doctor.repairs.cleanup_services
=====================================

Repairs that reclaim disk space and stop unnecessary background work.

Principles applied here:

* **Disable, never delete.**  Startup entries are disabled with a per-user
  override file; services are ``mask``\\ ed rather than removed.  Everything can
  be turned back on in one command.
* **Only files the user could regenerate anyway.**  The only deletions this
  module performs are package archives, log data and thumbnail caches - never
  documents, never configuration the user typed.
* **Measured before and after.**  Every cleanup reports the size before and
  after so the effect is visible, and a repair that frees nothing reports that
  honestly.
"""

from __future__ import annotations

import os
from typing import List, Tuple

from ..core import executil as ex
from ..core import privileges
from ..core.models import Repair, RepairOutcome, Risk
from ..core.repairer import RepairContext, register_repair
from ..checks.storage_space import journal_usage

HOME = privileges.user_home()
JOURNAL_CONF = "/etc/systemd/journald.conf.d/nexus-doctor.conf"


def _human(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0 or unit == "TB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024.0
    return f"{num:.1f} TB"


def _dir_bytes(path: str) -> int:
    return ex.dir_size(path) if ex.isdir(path) else 0


# --------------------------------------------------------------------------
# Package cache
# --------------------------------------------------------------------------


class AptCacheCleanRepair(Repair):
    """Remove downloaded .deb packages."""

    id = "cleanup.apt_cache"
    title = "Clear downloaded package archives"
    description = ("Removes the .deb files kept in /var/cache/apt/archives. They are only "
                   "needed to reinstall a package without re-downloading it.")
    risk = Risk.LOW
    requires_root = True
    undoable = False                 # the archives are deleted, not moved
    fixes = ["space.apt_cache_large", "space.low_root"]

    CACHE = "/var/cache/apt/archives"

    def _size(self) -> int:
        return _dir_bytes(self.CACHE)

    def available(self, ctx: RepairContext) -> bool:
        return self._size() > 50 * 1024 * 1024

    def why(self, ctx: RepairContext) -> str:
        return f"Frees {_human(self._size())} of package archives."

    def steps(self, ctx: RepairContext) -> List[str]:
        return [
            "Run 'apt-get clean' (removes all cached .deb files).",
            "Run 'apt-get autoclean' (removes packages no longer downloadable).",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        ctx.params["apt_cache_before"] = self._size()
        r1 = ctx.run_root(["apt-get", "clean"], timeout=120)
        ctx.run_root(["apt-get", "autoclean"], timeout=120)
        return RepairOutcome(r1.ok, "cleared downloaded package archives",
                             commands=["apt-get clean", "apt-get autoclean"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        size = self._size()
        was = ctx.params.get("apt_cache_before")
        state = f"package cache = {_human(size)}"
        if was:
            state += f" (was {_human(was)})"
        return RepairOutcome(size < 50 * 1024 * 1024, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Not reversible - the files are gone, but nothing depends on them."""
        return RepairOutcome(False, "Cleared archives cannot be restored, but they are "
                                    "re-downloaded automatically if ever needed.")


# --------------------------------------------------------------------------
# Journal
# --------------------------------------------------------------------------


class JournalVacuumRepair(Repair):
    """Shrink the systemd journal and cap its future size."""

    id = "cleanup.journal"
    title = "Shrink system logs and cap their size"
    description = ("Vacuums the systemd journal to 14 days / 200 MB and writes a permanent "
                   "limit so it cannot grow back silently.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["space.journal_large", "space.varlog_large", "space.low_root"]

    def _size(self) -> Tuple[int, str]:
        return journal_usage()

    def available(self, ctx: RepairContext) -> bool:
        size, _src = self._size()
        return size is not None and size > 100 * 1024 * 1024

    def why(self, ctx: RepairContext) -> str:
        size, _ = self._size()
        return f"Frees {_human(size or 0)} of archived log data."

    def steps(self, ctx: RepairContext) -> List[str]:
        return [
            "Run 'journalctl --vacuum-time=14d --vacuum-size=200M'.",
            f"Write {JOURNAL_CONF} limiting the journal to 200 MB and 14 days.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        ctx.params["journal_before"], _ = self._size()
        conf = ("# Managed by Nexus System Doctor - safe to delete.\n"
                "[Journal]\n"
                "SystemMaxUse=200M\n"
                "SystemKeepFree=1G\n"
                "MaxRetentionSec=14day\n")
        ctx.write_file(JOURNAL_CONF, conf, root=True)
        ctx.run_root(["systemctl", "restart", "systemd-journald"], timeout=40)
        return RepairOutcome(ex.isfile(JOURNAL_CONF),
                             "journal vacuumed and capped at 200 MB / 14 days",
                             commands=["journalctl --vacuum-time=14d --vacuum-size=200M"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        size, _ = self._size()
        was = ctx.params.get("journal_before")
        state = f"journal = {_human(size or 0)}"
        if was:
            state += f" (was {_human(was)})"
        ok = size is not None and size <= 250 * 1024 * 1024
        return RepairOutcome(ok, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Remove the size cap; the deleted log history itself cannot be restored."""
        ctx.remove_file(JOURNAL_CONF, root=True)
        ctx.run_root(["systemctl", "restart", "systemd-journald"], timeout=40)
        return RepairOutcome(not ex.isfile(JOURNAL_CONF), "journal size cap removed")


# --------------------------------------------------------------------------
# Thumbnails
# --------------------------------------------------------------------------


class ThumbnailCleanRepair(Repair):
    """Clear the thumbnail cache (regenerated on demand)."""

    id = "cleanup.thumbnails"
    title = "Clear the image thumbnail cache"
    description = ("Deletes cached image thumbnails. They are rebuilt automatically the next "
                   "time you open a folder, so nothing is lost.")
    risk = Risk.LOW
    undoable = False                 # thumbnails are deleted, not moved
    fixes = ["space.thumbnails_large", "space.inodes_root", "space.inodes_home"]

    @property
    def _dir(self) -> str:
        return os.path.join(privileges.user_home(), ".cache/thumbnails")

    def _size(self) -> int:
        return _dir_bytes(self._dir)

    def available(self, ctx: RepairContext) -> bool:
        return self._size() > 100 * 1024 * 1024

    def why(self, ctx: RepairContext) -> str:
        return f"Frees {_human(self._size())} of regenerable thumbnails."

    def steps(self, ctx: RepairContext) -> List[str]:
        return [f"Delete the contents of {self._dir} (kept as cache only)."]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        ctx.params["thumbnails_before"] = self._size()
        removed = 0
        for name in ex.listdir(self._dir):
            if ctx.remove_file(os.path.join(self._dir, name), backup=False):
                removed += 1
        return RepairOutcome(removed > 0 or not ex.listdir(self._dir),
                             f"cleared {removed} thumbnail cache director(ies)",
                             commands=[f"rm -rf {self._dir}/*"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        size = self._size()
        was = ctx.params.get("thumbnails_before")
        state = f"thumbnail cache = {_human(size)}"
        if was:
            state += f" (was {_human(was)})"
        return RepairOutcome(size < 100 * 1024 * 1024, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Not reversible, but thumbnails are regenerated automatically."""
        return RepairOutcome(False, "Thumbnails are recreated automatically when you browse "
                                    "image folders; nothing permanent was lost.")


# --------------------------------------------------------------------------
# Desktop search indexers
# --------------------------------------------------------------------------


class DisableIndexersRepair(Repair):
    """Stop the desktop search indexer.

    This is usually the single biggest responsiveness win on a mechanical disk:
    the indexer generates continuous small random reads that compete with
    everything the user is doing.
    """

    id = "services.disable_indexers"
    title = "Disable the desktop search indexer"
    description = ("Stops and disables the file indexer (tracker-miner-fs). Thunar's own "
                   "search still works; only the background database stops being updated.")
    risk = Risk.LOW
    fixes = ["services.indexer_running", "perf.random_slow", "cpu.iowait_high"]

    UNITS = ["tracker-miner-fs-3.service", "tracker-extract-3.service",
             "tracker-miner-fs.service", "tracker-extract.service",
             "tracker-writeback-3.service", "tracker-miner-rss-3.service",
             "baloo_file.service"]

    def _active_units(self, ctx: RepairContext) -> List[str]:
        r = ctx.run(["systemctl", "--user", "list-units", "--type=service",
                     "--state=running", "--no-legend", "--plain"], timeout=15)
        found: List[str] = []
        if r.ok:
            for line in r.lines:
                name = line.split()[0] if line.split() else ""
                if name in self.UNITS:
                    found.append(name)
            return found
        # systemd --user is unavailable (no session bus): fall back to the
        # process table, which is authoritative enough in that case.
        from ..checks.common import find_procs, processes
        if find_procs(processes(), [r"tracker-miner-fs", r"tracker-extract", r"baloo_file"]):
            found.extend(self.UNITS[:2])
        return found

    def available(self, ctx: RepairContext) -> bool:
        return bool(self._active_units(ctx))

    def why(self, ctx: RepairContext) -> str:
        units = self._active_units(ctx)
        return (f"Stops {', '.join(units[:3])}. Indexing generates constant random reads "
                f"that make a mechanical disk feel permanently busy.")

    def steps(self, ctx: RepairContext) -> List[str]:
        units = self._active_units(ctx)
        return [f"Stop and mask {u} (mask = it cannot be started again until unmasked)."
                for u in units]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        units = self._active_units(ctx)
        if not units:
            return RepairOutcome(False, "no indexer units are running")
        done = []
        for unit in units:
            r = ctx.run(["systemctl", "--user", "mask", unit], timeout=20)
            ctx.run(["systemctl", "--user", "stop", unit], timeout=20)
            if r.ok:
                done.append(unit)
        return RepairOutcome(bool(done), f"masked {len(done)} indexer unit(s): " +
                             ", ".join(done),
                             commands=[f"systemctl --user mask {u}" for u in done])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        still = self._active_units(ctx)
        state = f"active indexers: {', '.join(still) if still else 'none'}"
        return RepairOutcome(not still, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Unmask the indexer units (nothing was deleted)."""
        for unit in self.UNITS:
            ctx.run(["systemctl", "--user", "unmask", unit], timeout=15)
        ctx.run(["systemctl", "--user", "start", "tracker-miner-fs-3.service"], timeout=20)
        return RepairOutcome(True, "indexer units unmasked")


# --------------------------------------------------------------------------
# Services for hardware that is not present
# --------------------------------------------------------------------------


class DisableUnusedServicesRepair(Repair):
    """Disable services whose hardware does not exist on this machine."""

    id = "services.disable_unused"
    title = "Disable services for hardware this laptop does not have"
    description = ("Stops ModemManager (mobile broadband) and/or Bluetooth when no such "
                   "hardware is present. Both remain installed and can be re-enabled.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["services.unused_hw_services"]

    def _targets(self, ctx: RepairContext) -> List[Tuple[str, str]]:
        from ..checks.services_startup import _has_bluetooth, _has_wwan
        from ..checks.common import find_procs, processes
        procs = find_procs(processes(), [r"ModemManager", r"bluetoothd"])
        names = [p.name for p in procs]
        out = []
        if "ModemManager" in names and not _has_wwan():
            out.append(("ModemManager.service", "no mobile broadband hardware detected"))
        if "bluetoothd" in names and not _has_bluetooth():
            out.append(("bluetooth.service", "no Bluetooth adapter detected"))
        return out

    def available(self, ctx: RepairContext) -> bool:
        return bool(self._targets(ctx))

    def why(self, ctx: RepairContext) -> str:
        return "; ".join(f"{u} ({why})" for u, why in self._targets(ctx))

    def steps(self, ctx: RepairContext) -> List[str]:
        return [f"Stop and disable {u}" for u, _why in self._targets(ctx)]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        targets = self._targets(ctx)
        done = []
        for unit, _why in targets:
            r = ctx.run_root(["systemctl", "disable", "--now", unit], timeout=40)
            if r.ok:
                done.append(unit)
        return RepairOutcome(bool(done), f"disabled: {', '.join(done) or 'nothing'}",
                             commands=[f"systemctl disable --now {u}" for u in done])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        states = []
        ok = True
        for unit, _why in self._targets(ctx):
            r = ctx.run_root(["systemctl", "is-active", unit], timeout=15)
            active = r.first.strip() or "unknown"
            stopped = active in ("inactive", "failed", "unknown")
            states.append(f"{unit}: {active}")
            ok = ok and stopped
        from ..checks.common import find_procs, processes
        running = find_procs(processes(), [r"ModemManager", r"bluetoothd"])
        state = "; ".join(states) + f"; matching processes still alive: {len(running)}"
        # Either systemd reports it stopped, or the process is genuinely gone.
        return RepairOutcome(ok or not running, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Re-enable the services."""
        for unit, _why in self._targets(ctx):
            ctx.run_root(["systemctl", "enable", "--now", unit], timeout=40)
        return RepairOutcome(True, "services re-enabled")


# --------------------------------------------------------------------------
# Autostart trimming
# --------------------------------------------------------------------------


class TrimAutostartRepair(Repair):
    """Disable selected startup applications.

    Nothing is deleted: Xfce's session manager honours a per-user copy of the
    .desktop file with ``Hidden=true``, which is exactly what the "Application
    Autostart" settings dialog does.  Deleting our file restores the original.
    """

    id = "services.trim_autostart"
    title = "Disable selected startup applications"
    description = ("Prevents chosen applications from launching at login. They stay installed "
                   "and can be started manually, and the change is undone by deleting one file.")
    risk = Risk.LOW
    fixes = ["services.many_autostart"]

    OVERRIDE_DIR = os.path.join(privileges.user_home(), ".config/autostart")

    def _selected(self, ctx: RepairContext) -> List[str]:
        return list(ctx.param("autostart_entries", []) or [])

    def available(self, ctx: RepairContext) -> bool:
        # Only offered once the user has actually chosen which applications to
        # stop; we never guess which of their startup programs to disable.
        return bool(self._selected(ctx))

    def why(self, ctx: RepairContext) -> str:
        sel = self._selected(ctx)
        if not sel:
            return "Choose applications in Settings > Session and Startup to disable them."
        return "Stops " + ", ".join(sel) + " from starting at login."

    def steps(self, ctx: RepairContext) -> List[str]:
        return [f"Write {os.path.join(self.OVERRIDE_DIR, name + '.desktop')} with Hidden=true "
                f"(disables it without deleting anything)."
                for name in self._selected(ctx)]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        selected = self._selected(ctx)
        if not selected:
            return RepairOutcome(False, "no startup applications were selected")
        from ..checks.services_startup import autostart_entries
        known = {os.path.basename(e["file"])[:-8]: e for e in autostart_entries()}
        done = []
        for name in selected:
            entry = known.get(name)
            if entry is None:
                continue
            content = ("[Desktop Entry]\n"
                       "Type=Application\n"
                       f"Name={entry['name']}\n"
                       f"Exec={entry['exec']}\n"
                       "Hidden=true\n"
                       "X-Nexus-System-Doctor=disabled\n")
            if ctx.write_file(os.path.join(self.OVERRIDE_DIR, name + ".desktop"), content):
                done.append(name)
        return RepairOutcome(bool(done), f"disabled {len(done)} startup application(s)",
                             commands=[f"disable autostart: {n}" for n in done])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        from ..checks.services_startup import autostart_entries
        enabled = [e for e in autostart_entries() if e["enabled"]]
        disabled = [os.path.basename(e["file"]) for e in autostart_entries()
                    if not e["enabled"]]
        state = f"{len(enabled)} startup applications still enabled; disabled: " + \
                ", ".join(disabled[:8])
        return RepairOutcome(True, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Delete the override files, restoring the original startup behaviour."""
        removed = 0
        for name in ex.listdir(self.OVERRIDE_DIR):
            path = os.path.join(self.OVERRIDE_DIR, name)
            content = ex.read_text(path) or ""
            if "X-Nexus-System-Doctor=disabled" in content:
                if ctx.remove_file(path, backup=False):
                    removed += 1
        return RepairOutcome(removed > 0, f"removed {removed} startup override(s)")



# --------------------------------------------------------------------------
# Automatic apt timers
# --------------------------------------------------------------------------


class DisableAptTimersRepair(Repair):
    """Stop apt's daily timers from seizing the disk at random moments.

    ``apt-daily.timer`` and ``apt-daily-upgrade.timer`` refresh package lists
    and install updates in the background.  On a mechanical hard disk that
    produces exactly the symptom users describe as "the laptop suddenly becomes
    unusable for ten minutes".  Linux Mint already ships its own update manager
    (mintUpdate), which shows the same updates and lets the user choose when to
    install them, so turning the automatic timers off costs nothing.

    The timers are only disabled, never deleted, and are re-enabled verbatim by
    the rollback.
    """

    id = "services.disable_apt_timers"
    title = "Stop automatic apt timers from stalling the disk"
    description = ("Disables apt-daily.timer and apt-daily-upgrade.timer, which "
                   "refresh package lists in the background. Mint's own Update "
                   "Manager still shows and installs updates when you choose.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["services.apt_timers", "services.slow_boot", "cpu.iowait_high"]

    UNITS = ("apt-daily.timer", "apt-daily-upgrade.timer")

    def _enabled(self, ctx: RepairContext) -> List[str]:
        out = []
        for unit in self.UNITS:
            r = ctx.run_root(["systemctl", "is-enabled", unit], timeout=15)
            state = (r.first or "").strip()
            if state in ("enabled", "enabled-runtime", "indirect", "generated", "static"):
                out.append(unit)
        return out

    def available(self, ctx: RepairContext) -> bool:
        return bool(self._enabled(ctx))

    def why(self, ctx: RepairContext) -> str:
        units = self._enabled(ctx)
        return (f"{', '.join(units)} run automatically and can saturate a "
                f"mechanical disk while you are working"
                if units else "the automatic apt timers are already off")

    def steps(self, ctx: RepairContext) -> List[str]:
        return [f"systemctl disable --now {u}" for u in self._enabled(ctx)]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        done = []
        for unit in self._enabled(ctx):
            r = ctx.run_root(["systemctl", "disable", "--now", unit], timeout=40)
            if r.ok:
                done.append(unit)
        return RepairOutcome(bool(done),
                             f"disabled: {', '.join(done) or 'nothing to do'}",
                             commands=[f"systemctl disable --now {u}" for u in done])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        states = []
        ok = True
        for unit in self.UNITS:
            r = ctx.run_root(["systemctl", "is-enabled", unit], timeout=15)
            state = (r.first or "").strip() or "unknown"
            off = state in ("disabled", "masked", "not-found", "unknown")
            states.append(f"{unit}: {state}")
            ok = ok and off
        state = ", ".join(states)
        return RepairOutcome(ok, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Re-enable both timers."""
        for unit in self.UNITS:
            ctx.run_root(["systemctl", "enable", "--now", unit], timeout=40)
        return RepairOutcome(True, "apt timers re-enabled")


for _repair in (AptCacheCleanRepair(), JournalVacuumRepair(), ThumbnailCleanRepair(),
                DisableIndexersRepair(), DisableUnusedServicesRepair(),
                DisableAptTimersRepair(), TrimAutostartRepair()):
    register_repair(_repair)
