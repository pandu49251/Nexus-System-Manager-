"""
nexus_doctor.checks.system_config
=================================

Kernel tuning parameters that decide how the machine behaves under pressure.

These defaults were chosen for servers and for fast SSDs.  On a dual-core
laptop with 4 GB of RAM and a mechanical disk, three of them are actively
wrong, and changing them is free, reversible and measurable:

``vm.swappiness``
    How eagerly the kernel pages application memory out.  The default of 60
    was tuned when swap was on fast storage.  On a 5400 rpm disk, dropping the
    page cache is far cheaper than paging an application out.

``vm.dirty_*``
    How much dirty data may accumulate before it must be written.  The default
    allows roughly 10-20% of RAM, which on this machine means a single large
    copy can queue hundreds of megabytes; when the flush finally happens the
    desktop freezes until it completes.  Smaller values give frequent short
    flushes instead of one long freeze.

I/O scheduler
    Which algorithm orders requests to the disk.  ``none``/``kyber`` are tuned
    for fast NVMe devices; on a rotating disk, ``mq-deadline`` or ``bfq`` keep
    interactive tasks responsive.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..core import executil as ex
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import human_bytes, result

SCHEDULER_RE = re.compile(r"\[(\w[\w-]*)\]")


def current_scheduler(device: str) -> Optional[str]:
    text = ex.read_text(f"/sys/block/{device}/queue/scheduler")
    if not text:
        return None
    m = SCHEDULER_RE.search(text)
    return m.group(1) if m else None


def available_schedulers(device: str) -> List[str]:
    text = ex.read_text(f"/sys/block/{device}/queue/scheduler") or ""
    return [s for s in re.findall(r"(\w[\w-]*)", text) if s != "none" or "none" in text]


def sysctl_int(name: str) -> Optional[int]:
    v = ex.read_text("/proc/sys/" + name.replace(".", "/"))
    try:
        return int((v or "").strip())
    except ValueError:
        return None


@register("system_config", "System tuning for this hardware", Category.GENERAL,
          priority=55, description="swappiness, dirty ratios, I/O scheduler, mount options")
def check_system_config(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}

    root_dev = f.root_device()
    rotational = f.is_hdd(root_dev)
    facts["root_device"] = root_dev
    facts["rotational"] = rotational

    # ------------------------------------------------------ I/O scheduler
    sched = current_scheduler(root_dev) if root_dev else None
    facts["scheduler"] = sched
    facts["schedulers_available"] = available_schedulers(root_dev) if root_dev else []
    if rotational and sched in ("none", "kyber"):
        better = "bfq" if "bfq" in facts["schedulers_available"] else "mq-deadline"
        findings.append(Finding(
            id="config.scheduler",
            title=f"I/O scheduler is '{sched}', which is tuned for fast SSDs, not a hard disk",
            category=Category.STORAGE, severity=Severity.MEDIUM,
            summary=(f"The '{sched}' scheduler performs no reordering to reduce head "
                     f"movement. On a rotating disk that means requests are serviced in "
                     f"the order they arrive, so the head seeks back and forth."),
            root_cause=("Modern kernels default to 'none' or 'kyber', which are correct for "
                        "NVMe SSDs but a poor match for a mechanical drive."),
            impact="Slower simultaneous I/O and less responsive interactive tasks.",
            evidence=[Evidence(source=f"/sys/block/{root_dev}/queue/scheduler",
                               detail=f"current: {sched}; available: {', '.join(facts['schedulers_available'])}",
                               raw=ex.read_text(f"/sys/block/{root_dev}/queue/scheduler") or "",
                               command=f"cat /sys/block/{root_dev}/queue/scheduler")],
            confidence=Confidence.DIRECT,
            recommendations=[f"Use '{better}' for this disk. It applies immediately and is "
                             f"easily reverted."],
            repair_ids=["storage.io_scheduler"],
            data={"current": sched, "recommended": better},
        ))

    # ------------------------------------------------------------ noatime
    for m in f.mounts:
        mp = m.get("mountpoint")
        if mp not in ("/", "/home"):
            continue
        fstype = m.get("fstype", "")
        opts = [o for o in m.get("options", "").split(",") if o]
        if not fstype.startswith(("ext", "xfs", "btrfs", "f2fs")):
            continue
        if "noatime" in opts or "nodiratime" in opts:
            continue
        facts.setdefault("atime", {})[mp] = m.get("options")
        findings.append(Finding(
            id=f"config.atime_{mp.strip('/') or 'root'}",
            title=f"{mp} updates file access times on every read ('{m.get('options')}')",
            category=Category.FILESYSTEM, severity=Severity.LOW,
            summary=("Every time a file is read, the filesystem writes a timestamp back to "
                     "disk. Reading a thousand small files therefore causes a thousand "
                     "extra writes."),
            root_cause="The 'relatime' default still writes on many reads; on a mechanical "
                       "disk these extra writes compete with real work.",
            impact="Measurable extra disk traffic during any activity that reads many files "
                   "(browsing, indexing, launching applications).",
            evidence=[Evidence(source="/proc/mounts",
                               detail=f"{m.get('device')} on {mp} ({fstype}) options: {m.get('options')}",
                               command="cat /proc/mounts")],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Mount with 'noatime'. Access times are rarely needed on a desktop (mail "
                "clients and some backup tools are the exception).",
            ],
            repair_ids=["storage.noatime"],
            data={"mount": mp, "fstype": fstype},
        ))

    # -------------------------------------------------------- dirty ratios
    dirty_ratio = sysctl_int("vm.dirty_ratio")
    dirty_bg = sysctl_int("vm.dirty_background_ratio")
    dirty_bytes = sysctl_int("vm.dirty_bytes")
    dirty_bg_bytes = sysctl_int("vm.dirty_background_bytes")
    vfs_cache = sysctl_int("vm.vfs_cache_pressure")
    facts.update({"dirty_ratio": dirty_ratio, "dirty_background_ratio": dirty_bg,
                  "dirty_bytes": dirty_bytes, "dirty_background_bytes": dirty_bg_bytes,
                  "vfs_cache_pressure": vfs_cache})
    total_mb = f.mem_total_mb()
    if rotational and (dirty_ratio is not None and dirty_ratio >= 15) and total_mb:
        pending_mb = int(total_mb * dirty_ratio / 100)
        findings.append(Finding(
            id="config.dirty_ratio",
            title=f"Up to {pending_mb} MB of unsaved data can accumulate before writing ({dirty_ratio}% of RAM)",
            category=Category.MEMORY, severity=Severity.LOW,
            summary=(f"vm.dirty_ratio={dirty_ratio}% allows roughly {pending_mb} MB of "
                     f"modified data to pile up in RAM. When the limit is reached the kernel "
                     f"flushes everything at once, and because the disk manages only about "
                     f"100 MB/s, the desktop stalls for seconds."),
            root_cause="The default dirty limits are proportional to RAM and were sized for "
                       "servers with fast storage.",
            impact="Periodic multi-second freezes during file copies, downloads and updates.",
            evidence=[Evidence(source="/proc/sys/vm/dirty_ratio",
                               detail=f"dirty_ratio={dirty_ratio}, dirty_background_ratio={dirty_bg}, "
                                      f"MemTotal={total_mb} MB -> up to ~{pending_mb} MB buffered",
                               command="sysctl vm.dirty_ratio vm.dirty_background_ratio")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "Set smaller absolute limits (e.g. 32 MB background / 128 MB hard limit) so "
                "writes are flushed in small, frequent batches instead of one long stall.",
            ],
            repair_ids=["storage.dirty_ratio"],
            data={"dirty_ratio": dirty_ratio, "pending_mb": pending_mb},
        ))

    # -------------------------------------------------- OOM early warning
    has_guard = (f.has_package("earlyoom") or f.has_package("nohang") or
                 ex.exists("/usr/lib/systemd/systemd-oomd") or
                 ex.find_tool("earlyoom") is not None)
    facts["oom_guard"] = has_guard
    if not has_guard and total_mb and total_mb <= 6144:
        findings.append(Finding(
            id="config.no_oom_guard",
            title="Nothing intervenes before the kernel's out-of-memory killer strikes",
            category=Category.MEMORY, severity=Severity.LOW,
            summary=("With 4 GB of RAM the built-in OOM killer reacts only at the last "
                     "moment, and it picks whatever process it likes - often the desktop "
                     "itself. A userspace daemon can sacrifice the biggest memory hog first, "
                     "seconds earlier."),
            root_cause="earlyoom / nohang / systemd-oomd are not installed by default on Mint.",
            impact="The whole session can be killed instead of one runaway application.",
            evidence=[Evidence(source="package and binary check",
                               detail="earlyoom: not found; nohang: not found; systemd-oomd: not found",
                               command="dpkg -l earlyoom nohang; ls /usr/lib/systemd/systemd-oomd")],
            confidence=Confidence.MEASURED, needs_network=True,
            recommendations=["Install one: sudo apt install earlyoom (starts automatically)."],
            manual=True,
        ))

    # ------------------------------------------------------- zram status
    has_zram = any(d["name"].startswith("zram") for d in f.block_devices) or \
        f.has_module("zram")
    facts["zram_present"] = has_zram
    ctx.share("zram.present", has_zram)

    if not findings:
        findings.append(Finding(
            id="config.ok",
            title="System tuning already suits this hardware",
            category=Category.GENERAL, severity=Severity.OK,
            summary=f"Scheduler: {sched or 'n/a'}; swappiness handled by the Memory check; "
                    f"no problematic defaults found.",
            evidence=[Evidence(source="/sys and /proc/sys",
                               detail=f"scheduler={sched}, dirty_ratio={dirty_ratio}",
                               command="cat /sys/block/*/queue/scheduler; sysctl vm.dirty_ratio")],
            confidence=Confidence.MEASURED))

    return result("system_config", "System tuning for this hardware", Category.GENERAL,
                  findings, facts=facts)
