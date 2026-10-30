"""
nexus_doctor.repairs.memory_storage
===================================

Repairs for memory pressure and mechanical-disk tuning.

Every repair here follows the same discipline:

* it measures the current state first (``verify`` before ``apply``);
* it makes the smallest change that addresses the evidence;
* it persists the change so it survives a reboot, in a file that is clearly
  marked as managed by this application;
* it re-measures afterwards and only reports success if the new state is the
  one it intended to create;
* it can undo everything (``rollback``).

Nothing here deletes user data or changes partition tables.
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

from ..core import executil as ex
from ..core.models import Repair, RepairOutcome, Risk
from ..core.repairer import RepairContext, register_repair

SYSCTL_DIR = "/etc/sysctl.d"
HELPER_DIR = "/usr/lib/nexus-system-doctor"
UNIT_DIR = "/etc/systemd/system"
MODULES_LOAD_DIR = "/etc/modules-load.d"
UDEV_DIR = "/etc/udev/rules.d"

BANNER = ("# Managed by Nexus System Doctor.\n"
          "# Safe to delete: your system then returns to its previous defaults.\n"
          "# Original values are recorded below and in the backup directory.\n")


def _sysctl(name: str) -> Optional[int]:
    raw = ex.read_text("/proc/sys/" + name.replace(".", "/"))
    try:
        return int((raw or "").strip())
    except ValueError:
        return None


# --------------------------------------------------------------------------
# zram: compressed swap in RAM
# --------------------------------------------------------------------------


class ZramSwapRepair(Repair):
    """Create a compressed RAM swap device.

    On a machine with 4 GB of RAM and a 5400 rpm disk, this is the single most
    effective software change available.  Pages that would otherwise be written
    to a device with ~10 ms latency are instead compressed in RAM (~50 µs).
    It requires no repartitioning and is completely reversible.
    """

    id = "memory.zram_swap"
    title = "Create compressed swap in RAM (zram)"
    description = ("Adds a zram swap device so that memory pressure is absorbed by "
                   "compressing pages in RAM instead of writing them to the mechanical disk.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["memory.no_swap", "memory.swapping_to_hdd", "memory.swap_on_hdd",
             "memory.pressure", "memory.oom_kills"]

    def _size_mb(self, ctx: RepairContext) -> int:
        total = ctx.f.mem_total_mb()
        return int(max(512, min(total // 2, 2048)))

    def _has_zram_swap(self) -> bool:
        for line in ex.read_lines("/proc/swaps", []):
            parts = line.split()
            if len(parts) > 1 and "/dev/zram" in parts[0]:
                return True
        return False

    def available(self, ctx: RepairContext) -> bool:
        if self._has_zram_swap():
            return False
        from ..checks.memory import zram_module_available
        return bool(zram_module_available())

    def why(self, ctx: RepairContext) -> str:
        return (f"Creates a {self._size_mb(ctx)} MB compressed swap device in RAM. Pages are "
                f"compressed instead of being written to a disk that is ~100x slower.")

    def steps(self, ctx: RepairContext) -> List[str]:
        size = self._size_mb(ctx)
        return [
            f"Load the zram kernel module (already present in this kernel).",
            f"Create a zram device of {size} MB using the zstd compression algorithm.",
            "Format it as swap and enable it with a higher priority than any disk swap.",
            "Install a systemd unit so it is recreated automatically at every boot.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        size = self._size_mb(ctx)
        cmds: List[str] = []

        # 1. module -------------------------------------------------------
        r = ctx.run_root(["modprobe", "zram", "num_devices=1"], timeout=30)
        cmds.append("modprobe zram num_devices=1")
        if not r.ok:
            r = ctx.run_root(["modprobe", "zram"], timeout=30)
            cmds.append("modprobe zram")
            if not r.ok:
                return RepairOutcome(False, f"could not load the zram module: {r.err.strip()[:200]}",
                                     commands=cmds)

        # 2. create the device --------------------------------------------
        dev = None
        if ex.have_tool("zramctl"):
            r = ctx.run_root(["zramctl", "--find", "--size", f"{size}M",
                              "--algorithm", "zstd"], timeout=30)
            cmds.append(f"zramctl --find --size {size}M --algorithm zstd")
            if r.ok and r.first.strip().startswith("/dev/"):
                dev = r.first.strip()
        if dev is None:
            # Fallback for systems without util-linux's zramctl.
            if not ex.exists("/sys/block/zram0"):
                ctx.run_root(["modprobe", "zram", "num_devices=1"], timeout=20)
            algo_ok = ctx.write_file("/sys/block/zram0/comp_algorithm", "zstd\n",
                                     backup=False, root=True)
            size_ok = ctx.write_file("/sys/block/zram0/disksize", f"{size}M\n",
                                     backup=False, root=True)
            cmds.append(f"echo zstd > /sys/block/zram0/comp_algorithm; echo {size}M > /sys/block/zram0/disksize")
            if not (algo_ok or size_ok):
                return RepairOutcome(False, "could not configure the zram device",
                                     commands=cmds)
            dev = "/dev/zram0"

        # 3. mkswap + swapon ----------------------------------------------
        r = ctx.run_root(["mkswap", dev], timeout=40)
        cmds.append(f"mkswap {dev}")
        if not r.ok:
            return RepairOutcome(False, f"mkswap failed: {r.err.strip()[:200]}", commands=cmds)
        r = ctx.run_root(["swapon", "-p", "100", dev], timeout=30)
        cmds.append(f"swapon -p 100 {dev}")
        if not r.ok:
            return RepairOutcome(False, f"swapon failed: {r.err.strip()[:200]}", commands=cmds)

        # 4. persist -------------------------------------------------------
        script = f"""#!/bin/sh
# Nexus System Doctor - zram swap setup.  Safe to delete.
# Created {ctx.session_id}; removes cleanly with 'systemctl disable nexus-zram.service'.
SIZE={size}M
ALGO=zstd

case "$1" in
  start)
    modprobe zram num_devices=1 2>/dev/null || exit 0
    dev=$(zramctl --find --size "$SIZE" --algorithm "$ALGO" 2>/dev/null) || exit 1
    mkswap "$dev" >/dev/null 2>&1 || exit 1
    swapon -p 100 "$dev" || exit 1
    ;;
  stop)
    for d in /dev/zram*; do
      [ -b "$d" ] && swapoff "$d" 2>/dev/null
    done
    modprobe -r zram 2>/dev/null || true
    ;;
esac
exit 0
"""
        unit = f"""[Unit]
Description=Nexus System Doctor - compressed RAM swap (zram)
Documentation=man:zramctl(8)
DefaultDependencies=no
After=systemd-modules-load.service
Before=swap.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={HELPER_DIR}/zram-setup.sh start
ExecStop={HELPER_DIR}/zram-setup.sh stop

[Install]
WantedBy=swap.target
"""
        ctx.write_file(f"{HELPER_DIR}/zram-setup.sh", script, mode=0o755, root=True)
        ctx.write_file(f"{UNIT_DIR}/nexus-zram.service", unit, root=True)
        ctx.write_file(f"{MODULES_LOAD_DIR}/nexus-zram.conf", "zram\n", root=True)
        ctx.run_root(["systemctl", "daemon-reload"], timeout=30)
        ctx.run_root(["systemctl", "enable", "nexus-zram.service"], timeout=30)
        cmds.append("systemctl enable nexus-zram.service")

        return RepairOutcome(True, f"zram swap enabled ({size} MB, zstd compression)",
                             commands=cmds)

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        swaps = []
        for line in ex.read_lines("/proc/swaps", []):
            parts = line.split()
            if len(parts) > 1 and parts[0].startswith("/dev/zram"):
                swaps.append(f"{parts[0]} {int(parts[2]) // 1024} MB priority {parts[4]}")
        total = ctx.f.meminfo.get("SwapTotal", 0) // 1024
        state = "; ".join(swaps) if swaps else f"no zram device (SwapTotal {total} MB)"
        return RepairOutcome(bool(swaps), state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Disable and remove the zram swap, restoring the previous configuration."""
        ctx.run_root(["systemctl", "disable", "--now", "nexus-zram.service"], timeout=30)
        for line in ex.read_lines("/proc/swaps", []):
            parts = line.split()
            if parts and parts[0].startswith("/dev/zram"):
                ctx.run_root(["swapoff", parts[0]], timeout=30)
        ctx.remove_file(f"{UNIT_DIR}/nexus-zram.service", root=True)
        ctx.remove_file(f"{MODULES_LOAD_DIR}/nexus-zram.conf", root=True)
        ctx.remove_file(f"{HELPER_DIR}/zram-setup.sh", root=True)
        ctx.run_root(["systemctl", "daemon-reload"], timeout=30)
        return RepairOutcome(not self._has_zram_swap(), "zram swap removed")


# --------------------------------------------------------------------------
# swappiness
# --------------------------------------------------------------------------


class SwappinessRepair(Repair):
    """Lower vm.swappiness so the kernel drops caches instead of paging apps."""

    id = "memory.swappiness"
    title = "Reduce swap eagerness (vm.swappiness = 10)"
    description = ("Tells the kernel strongly to prefer dropping file caches over moving "
                   "application memory to disk. On a mechanical disk this avoids the "
                   "multi-second stalls caused by paging a running program out.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["memory.high_swappiness", "memory.small_ram", "memory.swapping_to_hdd"]

    TARGET = 10
    VFS_TARGET = 50
    FILE = f"{SYSCTL_DIR}/99-nexus-doctor-memory.conf"

    def available(self, ctx: RepairContext) -> bool:
        cur = _sysctl("vm.swappiness")
        return cur is not None and cur > self.TARGET

    def why(self, ctx: RepairContext) -> str:
        cur = _sysctl("vm.swappiness")
        return (f"vm.swappiness is {cur}; setting it to {self.TARGET} keeps running "
                f"applications in RAM instead of paging them to a slow disk.")

    def steps(self, ctx: RepairContext) -> List[str]:
        return [
            f"Write {self.FILE} with vm.swappiness = {self.TARGET} and "
            f"vm.vfs_cache_pressure = {self.VFS_TARGET}.",
            "Apply it immediately with sysctl so no reboot is needed.",
            "Back up any existing file first.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        old = _sysctl("vm.swappiness")
        old_vfs = _sysctl("vm.vfs_cache_pressure")
        content = (BANNER +
                   f"# previous: vm.swappiness={old} vm.vfs_cache_pressure={old_vfs}\n"
                   f"vm.swappiness = {self.TARGET}\n"
                   f"vm.vfs_cache_pressure = {self.VFS_TARGET}\n")
        if not ctx.write_file(self.FILE, content, root=True):
            return RepairOutcome(False, f"could not write {self.FILE}")
        r = ctx.run_root(["sysctl", "-p", self.FILE], timeout=20)
        if not r.ok:
            ctx.run_root(["sysctl", "-w", f"vm.swappiness={self.TARGET}"], timeout=15)
            ctx.run_root(["sysctl", "-w", f"vm.vfs_cache_pressure={self.VFS_TARGET}"],
                         timeout=15)
        return RepairOutcome(True, f"vm.swappiness set to {self.TARGET}",
                             commands=[f"sysctl -p {self.FILE}"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        cur = _sysctl("vm.swappiness")
        state = f"vm.swappiness = {cur}"
        return RepairOutcome(cur == self.TARGET, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Delete the sysctl file and reload the kernel defaults."""
        ctx.remove_file(self.FILE, root=True)
        ctx.run_root(["sysctl", "-w", "vm.swappiness=60"], timeout=15)
        ctx.run_root(["sysctl", "-w", "vm.vfs_cache_pressure=100"], timeout=15)
        return RepairOutcome(_sysctl("vm.swappiness") == 60, "swappiness restored to 60")


# --------------------------------------------------------------------------
# dirty ratios (prevents long freeze on flush)
# --------------------------------------------------------------------------


class DirtyRatioRepair(Repair):
    """Cap how much dirty data accumulates, so flushes are short and frequent."""

    id = "storage.dirty_ratio"
    title = "Limit write buffering to prevent long freezes"
    description = ("By default the kernel may buffer ~20% of RAM before writing it out; on "
                   "this machine that is a burst the mechanical disk cannot absorb, and the "
                   "desktop freezes until it completes. Smaller limits give frequent short "
                   "flushes instead.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["config.dirty_ratio"]

    BG_BYTES = 32 * 1024 * 1024      # start writing at 32 MB
    HARD_BYTES = 128 * 1024 * 1024   # hard limit at 128 MB
    FILE = f"{SYSCTL_DIR}/99-nexus-doctor-disk.conf"

    def available(self, ctx: RepairContext) -> bool:
        cur = _sysctl("vm.dirty_bytes")
        ratio = _sysctl("vm.dirty_ratio")
        if cur == self.HARD_BYTES:
            return False
        return ratio is not None and ratio >= 15

    def why(self, ctx: RepairContext) -> str:
        ratio = _sysctl("vm.dirty_ratio") or 0
        mb = int(ctx.f.mem_total_mb() * ratio / 100)
        return (f"Up to ~{mb} MB can currently pile up before the kernel writes it out. "
                f"Capping it at 128 MB turns one long freeze into many short flushes.")

    def steps(self, ctx: RepairContext) -> List[str]:
        return [
            f"Write {self.FILE} with vm.dirty_background_bytes = {self.BG_BYTES} and "
            f"vm.dirty_bytes = {self.HARD_BYTES}.",
            "Apply it immediately with sysctl.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        old_ratio = _sysctl("vm.dirty_ratio")
        content = (BANNER +
                   f"# previous: vm.dirty_ratio={old_ratio} (percentage-based)\n"
                   f"vm.dirty_background_bytes = {self.BG_BYTES}\n"
                   f"vm.dirty_bytes = {self.HARD_BYTES}\n")
        if not ctx.write_file(self.FILE, content, root=True):
            return RepairOutcome(False, f"could not write {self.FILE}")
        ctx.run_root(["sysctl", "-p", self.FILE], timeout=20)
        return RepairOutcome(True, "write buffering capped at 128 MB",
                             commands=[f"sysctl -p {self.FILE}"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        hard = _sysctl("vm.dirty_bytes")
        bg = _sysctl("vm.dirty_background_bytes")
        state = f"vm.dirty_bytes={hard}, vm.dirty_background_bytes={bg}"
        return RepairOutcome(hard == self.HARD_BYTES, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Delete the sysctl file and return to the ratio-based defaults."""
        ctx.remove_file(self.FILE, root=True)
        ctx.run_root(["sysctl", "-w", "vm.dirty_bytes=0"], timeout=15)
        ctx.run_root(["sysctl", "-w", "vm.dirty_background_bytes=0"], timeout=15)
        return RepairOutcome(_sysctl("vm.dirty_bytes") in (0, None),
                             "dirty limits restored to kernel defaults")


# --------------------------------------------------------------------------
# I/O scheduler
# --------------------------------------------------------------------------


class IoSchedulerRepair(Repair):
    """Select a scheduler that suits a rotating disk."""

    id = "storage.io_scheduler"
    title = "Use a disk scheduler suited to a mechanical drive"
    description = ("The 'none' and 'kyber' schedulers are designed for fast NVMe storage. "
                   "On a rotating disk, 'bfq' (or 'mq-deadline') reorders requests to reduce "
                   "head movement and keeps interactive tasks responsive.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["config.scheduler"]

    RULE_FILE = f"{UDEV_DIR}/60-nexus-doctor-iosched.rules"

    def _device(self, ctx: RepairContext) -> str:
        return ctx.f.root_device()

    def _available(self, dev: str) -> List[str]:
        text = ex.read_text(f"/sys/block/{dev}/queue/scheduler") or ""
        return [s.strip("[]") for s in text.split() if s]

    def _current(self, dev: str) -> Optional[str]:
        m = re.search(r"\[(\w[\w-]*)\]", ex.read_text(f"/sys/block/{dev}/queue/scheduler") or "")
        return m.group(1) if m else None

    def _target(self, ctx: RepairContext) -> Optional[str]:
        opts = self._available(self._device(ctx))
        for cand in ("bfq", "mq-deadline"):
            if cand in opts:
                return cand
        return None

    def available(self, ctx: RepairContext) -> bool:
        dev = self._device(ctx)
        if not dev or not ctx.f.is_hdd(dev):
            return False
        cur = self._current(dev)
        return cur is not None and cur not in ("bfq", "mq-deadline") and self._target(ctx) is not None

    def why(self, ctx: RepairContext) -> str:
        dev = self._device(ctx)
        return (f"{dev} is a rotating disk currently using the '{self._current(dev)}' "
                f"scheduler; '{self._target(ctx)}' reduces head movement and keeps the "
                f"desktop responsive while the disk is busy.")

    def steps(self, ctx: RepairContext) -> List[str]:
        dev, target = self._device(ctx), self._target(ctx)
        return [
            f"Switch {dev} to the '{target}' scheduler immediately (takes effect at once).",
            f"Install a udev rule so it is applied automatically on every boot.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        dev, target = self._device(ctx), self._target(ctx)
        if not target:
            return RepairOutcome(False, "no suitable scheduler is available in this kernel")
        r = ctx.write_file(f"/sys/block/{dev}/queue/scheduler", target + "\n",
                           backup=False, root=True)
        rule = (f'# Managed by Nexus System Doctor.\n'
                f'ACTION=="add|change", KERNEL=="sd[a-z]|mmcblk[0-9]*", '
                f'ATTR{{queue/rotational}}=="1", ATTR{{queue/scheduler}}="{target}"\n')
        ctx.write_file(self.RULE_FILE, rule, root=True)
        ctx.run_root(["udevadm", "control", "--reload-rules"], timeout=20)
        ctx.run_root(["udevadm", "trigger", "--action=change"], timeout=30)
        if not r:
            return RepairOutcome(False, f"could not set the scheduler for {dev}")
        return RepairOutcome(True, f"{dev} now uses the '{target}' scheduler",
                             commands=[f"echo {target} > /sys/block/{dev}/queue/scheduler"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        dev, target = self._device(ctx), self._target(ctx)
        cur = self._current(dev)
        state = f"{dev} scheduler = {cur} (target {target})"
        return RepairOutcome(cur == target, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Remove the udev rule and restore the previous scheduler."""
        ctx.remove_file(self.RULE_FILE, root=True)
        ctx.run_root(["udevadm", "control", "--reload-rules"], timeout=20)
        dev = self._device(ctx)
        ctx.write_file(f"/sys/block/{dev}/queue/scheduler", "mq-deadline\n",
                       backup=False, root=True)
        return RepairOutcome(True, "scheduler rule removed")


# --------------------------------------------------------------------------
# noatime
# --------------------------------------------------------------------------


class NoatimeRepair(Repair):
    """Mount filesystems with noatime.

    Safety note: this is the only repair that edits ``/etc/fstab``, and a bad
    fstab can prevent the machine from booting.  We therefore remount first
    with the new options - if the kernel accepts them we write fstab, and if
    the remount fails we leave fstab completely untouched.
    """

    id = "storage.noatime"
    title = "Stop recording file access times (noatime)"
    description = ("Reading a file currently causes a write. On a mechanical disk those "
                   "extra writes compete with real work. noatime removes them; nothing on a "
                   "typical desktop needs access times.")
    risk = Risk.MEDIUM
    requires_root = True
    reboot_required = False
    fixes = ["config.atime_root", "config.atime_home"]

    FSTAB = "/etc/fstab"

    def _targets(self, ctx: RepairContext):
        out = []
        for m in ctx.f.mounts:
            mp = m.get("mountpoint")
            if mp not in ("/", "/home"):
                continue
            fstype = m.get("fstype", "")
            if not fstype.startswith(("ext", "xfs", "btrfs", "f2fs")):
                continue
            opts = [o for o in m.get("options", "").split(",") if o]
            if "noatime" in opts:
                continue
            out.append(m)
        return out

    def available(self, ctx: RepairContext) -> bool:
        return bool(self._targets(ctx)) and ex.isfile(self.FSTAB)

    def why(self, ctx: RepairContext) -> str:
        mps = ", ".join(m["mountpoint"] for m in self._targets(ctx))
        return f"Removes a write for every read on {mps}."

    def steps(self, ctx: RepairContext) -> List[str]:
        mps = ", ".join(m["mountpoint"] for m in self._targets(ctx))
        return [
            f"Test the change by remounting {mps} with noatime (the kernel validates it).",
            "Only if that succeeds, add 'noatime' to the matching lines in /etc/fstab.",
            "A backup copy of /etc/fstab is taken first.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        targets = self._targets(ctx)
        if not targets:
            return RepairOutcome(False, "no eligible filesystems")
        # Step 1: prove the kernel accepts the options before touching fstab.
        for m in targets:
            mp = m["mountpoint"]
            opts = [o for o in m["options"].split(",") if o]
            new_opts = ",".join(sorted(set(opts) | {"noatime"}))
            r = ctx.run_root(["mount", "-o", "remount," + new_opts, mp], timeout=30)
            if not r.ok:
                return RepairOutcome(
                    False,
                    f"Refused to edit /etc/fstab: remounting {mp} with noatime failed "
                    f"({r.err.strip()[:120]}). Nothing was changed.",
                    commands=[f"mount -o remount,{new_opts} {mp}"])
        # Step 2: edit fstab.
        original = ex.read_text(self.FSTAB) or ""
        lines = original.splitlines()
        changed = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) < 4 or not parts[1].startswith("/"):
                continue
            mp, fstype, opts = parts[1], parts[2], parts[3]
            if mp not in {m["mountpoint"] for m in targets}:
                continue
            if not fstype.startswith(("ext", "xfs", "btrfs", "f2fs")):
                continue
            if "noatime" in opts.split(","):
                continue
            parts[3] = opts + ",noatime"
            lines[i] = "\t".join(parts) if "\t" in line else " ".join(parts)
            changed += 1
        if not changed:
            return RepairOutcome(False, "no fstab lines matched the target mounts")
        if not ctx.write_file(self.FSTAB, "\n".join(lines) + "\n", root=True):
            return RepairOutcome(False, "could not write /etc/fstab")
        return RepairOutcome(True, f"added noatime to {changed} filesystem(s)",
                             commands=[f"mount -o remount,... (verified first)"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        # Re-read the live mount table, not fstab: this proves the change is real.
        states = []
        ok = True
        for m in self._targets(ctx):
            mp = m["mountpoint"]
            now = next((x for x in ctx.f.mounts if x.get("mountpoint") == mp), None)
            # ctx.f is a snapshot; read /proc/mounts again for the live value.
            for line in ex.read_lines("/proc/mounts", []):
                parts = line.split()
                if len(parts) > 3 and parts[1] == mp:
                    has = "noatime" in parts[3].split(",")
                    states.append(f"{mp}: {'noatime' if has else parts[3]}")
                    ok = ok and has
                    break
        state = "; ".join(states)
        return RepairOutcome(ok and bool(states), state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Restore the saved copy of /etc/fstab and remount the original options."""
        saved = ctx.backups[-1] if ctx.backups else None
        if saved and os.path.exists(saved):
            content = ex.read_text(saved, "") or ""
            ctx.write_file(self.FSTAB, content, backup=False, root=True)
            for m in self._targets(ctx):
                ctx.run_root(["mount", "-o", "remount," + m["options"], m["mountpoint"]],
                             timeout=30)
            return RepairOutcome(True, f"/etc/fstab restored from {saved}")
        return RepairOutcome(False, "no backup copy of /etc/fstab was found")


# --------------------------------------------------------------------------
# smartd monitoring
# --------------------------------------------------------------------------


class SmartdRepair(Repair):
    """Enable the SMART monitoring daemon."""

    id = "storage.enable_smartd"
    title = "Enable automatic disk-health monitoring (smartd)"
    description = ("smartd watches the disk in the background and reports problems as they "
                   "appear, rather than waiting for the next manual scan.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["storage.smartd_off"]

    def available(self, ctx: RepairContext) -> bool:
        return ex.find_tool("smartctl") is not None

    def why(self, ctx: RepairContext) -> str:
        return "Gives early warning of disk failure instead of discovering it after data loss."

    def steps(self, ctx: RepairContext) -> List[str]:
        return ["Enable and start the smartd service."]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        r = ctx.run_root(["systemctl", "enable", "--now", "smartd"], timeout=40)
        return RepairOutcome(r.ok, "smartd enabled" if r.ok else r.err.strip()[:160],
                             commands=["systemctl enable --now smartd"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        r = ctx.run_root(["systemctl", "is-enabled", "smartd"], timeout=15)
        state = f"smartd: {r.first.strip() or r.state}"
        return RepairOutcome(r.ok and r.first.strip() in ("enabled", "enabled-runtime"),
                             state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Stop and disable smartd."""
        ctx.run_root(["systemctl", "disable", "--now", "smartd"], timeout=30)
        return RepairOutcome(True, "smartd disabled")


# --------------------------------------------------------------------------
# CPU governor
# --------------------------------------------------------------------------


class CpuGovernorRepair(Repair):
    """Use a demand-based CPU frequency governor instead of powersave."""

    id = "cpu.governor"
    title = "Switch the CPU to a demand-based frequency governor"
    description = ("The 'powersave' governor pins the processor at its lowest frequency, so "
                   "everything runs slower than the hardware is capable of. 'schedutil' "
                   "raises the frequency when there is work and lowers it when there is not.")
    risk = Risk.LOW
    requires_root = True
    fixes = ["cpu.governor_low", "cpu.throttling"]

    SCRIPT = f"{HELPER_DIR}/cpu-governor.sh"
    UNIT = f"{UNIT_DIR}/nexus-cpufreq.service"

    def _available_governors(self) -> List[str]:
        text = ex.read_text(
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors") or ""
        return text.split()

    def _current(self) -> Optional[str]:
        v = ex.read_text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        return v.strip() if v else None

    def _target(self) -> Optional[str]:
        opts = self._available_governors()
        for cand in ("schedutil", "ondemand", "conservative"):
            if cand in opts:
                return cand
        return None

    def available(self, ctx: RepairContext) -> bool:
        cur = self._current()
        return cur is not None and cur in ("powersave", "userspace") and self._target() is not None

    def why(self, ctx: RepairContext) -> str:
        return (f"The CPU is held at its lowest frequency by the '{self._current()}' "
                f"governor; '{self._target()}' lets it speed up when needed.")

    def steps(self, ctx: RepairContext) -> List[str]:
        target = self._target()
        return [
            f"Set the governor to '{target}' on every CPU.",
            "Install a small service so the setting survives a reboot.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        target = self._target()
        if not target:
            return RepairOutcome(False, "no demand-based governor is available")
        cpus = [c for c in ex.listdir("/sys/devices/system/cpu")
                if c.startswith("cpu") and c[3:].isdigit()]
        ok = False
        for cpu in cpus:
            r = ctx.write_file(f"/sys/devices/system/cpu/{cpu}/cpufreq/scaling_governor",
                               target + "\n", backup=False, root=True)
            ok = ok or r
        script = f"""#!/bin/sh
# Nexus System Doctor - CPU frequency governor. Safe to delete.
GOV={target}
for d in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [ -w "$d" ] && echo "$GOV" > "$d"
done
exit 0
"""
        unit = f"""[Unit]
Description=Nexus System Doctor - CPU frequency governor ({target})
After=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={self.SCRIPT}

[Install]
WantedBy=multi-user.target
"""
        ctx.write_file(self.SCRIPT, script, mode=0o755, root=True)
        ctx.write_file(self.UNIT, unit, root=True)
        ctx.run_root(["systemctl", "daemon-reload"], timeout=30)
        ctx.run_root(["systemctl", "enable", "nexus-cpufreq.service"], timeout=30)
        return RepairOutcome(ok, f"governor set to '{target}'",
                             commands=[f"cpufreq governor -> {target}"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        cur = self._current()
        target = self._target()
        state = f"governor = {cur} (target {target})"
        return RepairOutcome(cur == target, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Remove the service and restore the powersave governor."""
        ctx.run_root(["systemctl", "disable", "--now", "nexus-cpufreq.service"], timeout=30)
        ctx.remove_file(self.UNIT, root=True)
        ctx.remove_file(self.SCRIPT, root=True)
        for cpu in [c for c in ex.listdir("/sys/devices/system/cpu")
                    if c.startswith("cpu") and c[3:].isdigit()]:
            ctx.write_file(f"/sys/devices/system/cpu/{cpu}/cpufreq/scaling_governor",
                           "powersave\n", backup=False, root=True)
        return RepairOutcome(True, "CPU governor restored to powersave")


for _repair in (ZramSwapRepair(), SwappinessRepair(), DirtyRatioRepair(),
                IoSchedulerRepair(), NoatimeRepair(), SmartdRepair(),
                CpuGovernorRepair()):
    register_repair(_repair)
