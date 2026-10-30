"""
nexus_doctor.checks.memory
==========================

Memory and swap analysis.

On a 4 GB machine running a modern Xfce desktop, memory pressure is usually the
*first* cause of the "everything is slow" feeling, and it interacts badly with
a mechanical hard disk: when RAM runs out the kernel pages applications out to
a 5400 rpm drive that is ~100x slower than RAM, producing multi-second freezes
that look like "the laptop is broken".

Everything here is measured from ``/proc/meminfo``, ``/proc/swaps`` and the
process table.  No guessing.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from ..core import executil as ex
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import (human_bytes, match_lines, pct, processes, result,
                     top_memory_procs)

SWAP_LINE = re.compile(r"^(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)$")


def read_swaps() -> List[Dict[str, object]]:
    """Parse /proc/swaps into structured records."""
    out: List[Dict[str, object]] = []
    for line in ex.read_lines("/proc/swaps", []):
        if line.startswith("Filename") or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            size_kb = int(parts[2])
            used_kb = int(parts[3])
        except ValueError:
            continue
        out.append({
            "path": parts[0],
            "type": parts[1],
            "size_mb": size_kb // 1024,
            "used_mb": used_kb // 1024,
            "priority": parts[4],
        })
    return out


def zram_module_available() -> Optional[bool]:
    """True if the running kernel can provide zram, False if not, None unknown."""
    if ex.have_tool("modinfo"):
        r = ex.run(["modinfo", "zram"], timeout=8)
        if r.ok and "filename:" in r.out:
            return True
    kver = ex.kernel_version()
    base = f"/lib/modules/{kver}/kernel/drivers/block/zram"
    if ex.isdir(base):
        for name in ex.listdir(base):
            if name.startswith("zram") and (name.endswith(".ko") or ".ko." in name):
                return True
    # Already built in?
    if ex.exists("/sys/module/zram"):
        return True
    if ex.exists(f"/lib/modules/{kver}/modules.builtin"):
        txt = ex.read_text(f"/lib/modules/{kver}/modules.builtin") or ""
        if "zram" in txt:
            return True
    return False


def sysctl_value(name: str) -> Optional[str]:
    path = "/proc/sys/" + name.replace(".", "/")
    v = ex.read_text(path)
    return v.strip() if v else None


@register("memory", "Memory and swap", Category.MEMORY, priority=10,
          description="RAM pressure, swap configuration, OOM kills")
def check_memory(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}

    total_mb = f.mem_total_mb()
    avail_mb = f.mem_available_mb()
    total_kb = f.meminfo.get("MemTotal", 0)
    avail_kb = f.meminfo.get("MemAvailable", 0)
    swap_total_mb = f.meminfo.get("SwapTotal", 0) // 1024
    swap_free_mb = f.meminfo.get("SwapFree", 0) // 1024
    swap_used_mb = swap_total_mb - swap_free_mb
    swappiness = sysctl_value("vm.swappiness")
    facts.update({"total_mb": total_mb, "available_mb": avail_mb,
                  "swap_total_mb": swap_total_mb, "swap_used_mb": swap_used_mb,
                  "swappiness": swappiness})
    ctx.share("memory.total_mb", total_mb)
    ctx.share("memory.swap_total_mb", swap_total_mb)

    avail_pct = pct(avail_kb, total_kb, 1)
    swaps = read_swaps()
    facts["swaps"] = swaps

    procs = processes()
    facts["process_count"] = len(procs)

    # ---------------------------------------------------------------- RAM
    mem_ev = [
        Evidence(source="/proc/meminfo",
                 detail=f"MemTotal {total_mb} MB, MemAvailable {avail_mb} MB ({avail_pct}% free)",
                 raw=f"MemTotal:       {total_kb} kB\nMemAvailable:   {avail_kb} kB",
                 command="cat /proc/meminfo"),
    ]
    if total_mb and total_mb <= 4600:
        findings.append(Finding(
            id="memory.small_ram",
            title=f"Only {total_mb} MB of physical RAM is installed",
            category=Category.MEMORY,
            severity=Severity.MEDIUM,
            summary=(f"This machine has {total_mb} MB of RAM. That is below the ~8 GB a "
                     f"modern Linux desktop wants, so the kernel will be forced to "
                     f"reclaim memory constantly."),
            root_cause=("Installed RAM is small. Combined with a mechanical hard disk, "
                        "reclaiming memory means paging to a device roughly 100x slower "
                        "than RAM, which is what produces the multi-second freezes."),
            impact="Applications take seconds to respond after the disk LED stays lit.",
            evidence=mem_ev,
            confidence=Confidence.MEASURED,
            recommendations=[
                "Add compressed swap in RAM (zram) so pages are compressed instead of written to disk.",
                "Lower vm.swappiness so the kernel prefers dropping file caches over paging applications.",
                "If the RAM is upgradeable, 8 GB is the single biggest improvement available.",
            ],
            repair_ids=["memory.zram_swap", "memory.swappiness"],
            data={"total_mb": total_mb},
        ))

    # ------------------------------------------------------------ pressure
    if total_kb:
        if avail_pct < 10:
            sev, word = Severity.CRITICAL, "critically low"
        elif avail_pct < 18:
            sev, word = Severity.HIGH, "low"
        elif avail_pct < 30:
            sev, word = Severity.MEDIUM, "somewhat low"
        else:
            sev, word = None, "healthy"
        if sev is not None:
            top = top_memory_procs(procs, 5)
            ev = list(mem_ev)
            if top:
                ev.append(Evidence(
                    source="/proc/<pid>/statm",
                    detail="Largest memory consumers right now: " + ", ".join(
                        f"{p.name} {p.rss_mb} MB" for p in top),
                    raw="\n".join(f"{p.pid} {p.rss_mb} MB {p.cmdline[:90]}" for p in top),
                    command="for p in /proc/[0-9]*; do cat $p/statm; done"))
            findings.append(Finding(
                id="memory.pressure",
                title=f"Available memory is {word} ({avail_mb} MB of {total_mb} MB, {avail_pct}%)",
                category=Category.MEMORY,
                severity=sev,
                summary=(f"Only {avail_mb} MB ({avail_pct}%) of RAM is available for new "
                         f"work. The kernel is close to having to reclaim memory."),
                root_cause=("Working set of running applications approaches installed RAM. "
                            "On this hardware, reclamation means paging to a mechanical disk."),
                impact="Window switches, app launches and file opens stall while memory is reclaimed.",
                evidence=ev,
                confidence=Confidence.MEASURED,
                recommendations=[
                    "Close unused applications and browser tabs (see the list of top consumers).",
                    "Enable zram so reclaimed pages are compressed in RAM first.",
                    "Check for a memory leak: a process whose RSS keeps growing across reboots.",
                ],
                repair_ids=["memory.zram_swap"],
                data={"available_mb": avail_mb, "pct": avail_pct},
            ))

    # ---------------------------------------------------------------- swap
    if swap_total_mb == 0:
        zram_ok = zram_module_available()
        ev = list(mem_ev)
        ev.append(Evidence(source="/proc/swaps", detail="No swap device is configured at all.",
                           raw="Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n(no entries)",
                           command="cat /proc/swaps"))
        if zram_ok is not None:
            ev.append(Evidence(
                source="kernel module check",
                detail=("The running kernel provides the zram module, so compressed RAM swap "
                        "can be created without installing anything or partitioning the disk."
                        if zram_ok else
                        "The zram module was not found for this kernel; compressed swap may "
                        "not be available."),
                command="modinfo zram", root_required=False))
        findings.append(Finding(
            id="memory.no_swap",
            title="No swap space is configured",
            category=Category.MEMORY,
            severity=Severity.HIGH if total_mb <= 6144 else Severity.MEDIUM,
            summary=("With %d MB of RAM and no swap at all, exhausting memory leaves the "
                     "kernel no option but to invoke the out-of-memory killer, which "
                     "terminates applications instantly." % total_mb),
            root_cause=("No swap device exists. Swap is not only for emergencies: it also "
                        "lets the kernel evict rarely-used anonymous pages, which frees RAM "
                        "for the page cache and makes the desktop more responsive."),
            impact=("Applications disappear without warning under load; the desktop has no "
                    "safety margin; hibernation is impossible."),
            evidence=ev,
            confidence=Confidence.MEASURED,
            recommendations=[
                "Create a compressed zram swap device (fast, reversible, no repartitioning).",
                "Alternatively create a swapfile, but on a mechanical disk it will be slow.",
            ],
            repair_ids=["memory.zram_swap"] if zram_ok else [],
            manual=not zram_ok,
            data={"zram_available": zram_ok},
        ))
    else:
        on_disk = [s for s in swaps if s["type"] in ("file", "partition")]
        rotational = False
        for s in on_disk:
            dev = str(s["path"]).replace("/dev/", "")
            dev = re.sub(r"\d+$", "", dev)
            if f.is_hdd(dev):
                rotational = True
        if rotational and swap_used_mb > 64:
            findings.append(Finding(
                id="memory.swapping_to_hdd",
                title=f"System is actively swapping to a mechanical disk ({swap_used_mb} MB used)",
                category=Category.MEMORY,
                severity=Severity.HIGH,
                summary=(f"{swap_used_mb} MB of data has been paged out to a rotating disk. "
                         f"Every access to that data costs a physical seek (~10 ms), which "
                         f"is why the machine feels frozen rather than merely slow."),
                root_cause=("RAM pressure forces anonymous pages onto a device whose random "
                            "access latency is orders of magnitude worse than RAM."),
                impact="Multi-second freezes, stuttering audio, unresponsive windows.",
                evidence=[
                    Evidence(source="/proc/swaps",
                             detail="; ".join(f"{s['path']} {s['size_mb']}MB used={s['used_mb']}MB"
                                              for s in swaps),
                             raw="\n".join(ex.read_lines("/proc/swaps", [])),
                             command="cat /proc/swaps"),
                    Evidence(source=f"/sys/block/{f.root_device()}/queue/rotational",
                             detail="The swap device is on a rotating (mechanical) disk.",
                             command=f"cat /sys/block/{f.root_device()}/queue/rotational"),
                ],
                confidence=Confidence.MEASURED,
                recommendations=[
                    "Add zram and give it a higher priority than the disk swap, so the kernel "
                    "uses compressed RAM first.",
                    "Reduce memory usage or add RAM; disk swap on a 5400 rpm drive is a "
                    "last resort, not a solution.",
                ],
                repair_ids=["memory.zram_swap", "memory.swappiness"],
                data={"swap_used_mb": swap_used_mb},
            ))
        elif rotational:
            findings.append(Finding(
                id="memory.swap_on_hdd",
                title="Swap resides on a mechanical hard disk",
                category=Category.MEMORY,
                severity=Severity.LOW,
                summary=("Swap is configured on a rotating disk. That is acceptable as a "
                         "safety net, but once it is used the machine will feel frozen."),
                root_cause="Swap backing device is rotational; random I/O is ~10 ms per access.",
                evidence=[Evidence(source="/proc/swaps",
                                   detail="; ".join(f"{s['path']} {s['size_mb']}MB" for s in swaps),
                                   raw="\n".join(ex.read_lines("/proc/swaps", [])),
                                   command="cat /proc/swaps")],
                confidence=Confidence.MEASURED,
                recommendations=["Give zram a higher priority so RAM compression is tried first."],
                repair_ids=["memory.zram_swap"],
            ))

    # -------------------------------------------------------- swappiness
    if swappiness is not None and swap_total_mb > 0:
        try:
            sw = int(swappiness)
        except ValueError:
            sw = -1
        if sw >= 60 and any(f.is_hdd(re.sub(r"\d+$", "", str(s["path"]).replace("/dev/", "")))
                            for s in swaps):
            findings.append(Finding(
                id="memory.high_swappiness",
                title=f"vm.swappiness is {sw} on a machine with a mechanical disk",
                category=Category.MEMORY,
                severity=Severity.MEDIUM,
                summary=(f"swappiness={sw} makes the kernel eager to page out application "
                         f"memory in favour of keeping file caches. On a slow disk that "
                         f"trade is a bad one."),
                root_cause=("Default swappiness (60) is tuned for fast storage. With a "
                            "5400 rpm drive, paging application memory out costs far more "
                            "than re-reading a cached file."),
                impact="Applications get paged out while idle and stutter when you return to them.",
                evidence=[Evidence(source="/proc/sys/vm/swappiness", detail=f"vm.swappiness = {sw}",
                                   command="cat /proc/sys/vm/swappiness"),
                          Evidence(source="/proc/swaps",
                                   detail="; ".join(f"{s['path']}" for s in swaps),
                                   command="cat /proc/swaps")],
                confidence=Confidence.MEASURED,
                recommendations=["Set vm.swappiness to 10 so the kernel drops caches before paging apps."],
                repair_ids=["memory.swappiness"],
                data={"swappiness": sw},
            ))

    # ------------------------------------------------------------ OOM kills
    logs = ctx.shared_get("log.lines")
    if logs is None:
        from .common import kernel_messages
        logs = kernel_messages(400)
        ctx.share("log.lines", logs)
    oom = match_lines(logs, [r"Out of memory: Kill process", r"oom-kill:",
                             r"Memory cgroup out of memory", r"Killed process \d+"], limit=5)
    if oom:
        findings.append(Finding(
            id="memory.oom_kills",
            title=f"The kernel killed processes to free memory ({len(oom)} event(s) in this boot)",
            category=Category.MEMORY,
            severity=Severity.HIGH,
            summary=("The out-of-memory killer ran. Applications did not crash on their own "
                     "- the kernel terminated them because the system ran out of RAM."),
            root_cause=("Total memory demand exceeded RAM plus swap, so the kernel had to "
                        "sacrifice a process."),
            impact="Windows and applications vanish with no error dialog.",
            evidence=[Evidence(source="kernel log", detail=line[:180],
                               raw=line, command="journalctl -k -b | grep -i -E 'oom|killed process'")
                      for _p, line in oom],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Enable zram to increase effective memory capacity.",
                "Identify the largest consumer and reduce its footprint (browser tabs are the usual culprit).",
                "Consider installing earlyoom/nohang so memory pressure is handled before a hard OOM.",
            ],
            repair_ids=["memory.zram_swap"],
            data={"events": len(oom)},
        ))

    # --------------------------------------------------------- overcommit
    commit_limit = f.meminfo.get("CommitLimit", 0)
    committed = f.meminfo.get("Committed_AS", 0)
    if commit_limit and committed > commit_limit * 0.9:
        findings.append(Finding(
            id="memory.overcommit_high",
            title="Applications have reserved nearly all available memory",
            category=Category.MEMORY,
            severity=Severity.MEDIUM if committed > commit_limit else Severity.LOW,
            summary=(f"Committed_AS ({committed // 1024} MB) is at or above CommitLimit "
                     f"({commit_limit // 1024} MB): applications have asked for almost "
                     f"everything the kernel can promise."),
            root_cause="Memory reservations approach the commit limit (RAM + swap * overcommit ratio).",
            impact="Allocations may start failing and the OOM killer becomes likely.",
            evidence=[Evidence(source="/proc/meminfo",
                               detail=f"CommitLimit {commit_limit // 1024} MB, "
                                      f"Committed_AS {committed // 1024} MB "
                                      f"({pct(committed, commit_limit, 0)}% of limit)",
                               raw=f"CommitLimit:   {commit_limit} kB\nCommitted_AS:  {committed} kB",
                               command="grep -E 'CommitLimit|Committed_AS' /proc/meminfo")],
            confidence=Confidence.MEASURED,
            recommendations=["Add swap or zram; close memory-heavy applications."],
            repair_ids=["memory.zram_swap"],
        ))

    # ------------------------------------------------------------- zswap
    zswap_enabled = ex.read_text("/sys/module/zswap/parameters/enabled")
    facts["zswap_enabled"] = (zswap_enabled or "").strip()
    if facts["zswap_enabled"] == "N" and swap_total_mb == 0:
        findings.append(Finding(
            id="memory.zswap_off",
            title="zswap (compressed swap cache) is disabled",
            category=Category.MEMORY,
            severity=Severity.LOW,
            summary="zswap is compiled in but switched off, so pages are not compressed before being written out.",
            root_cause="Kernel parameter zswap.enabled is N by default on most distributions.",
            evidence=[Evidence(source="/sys/module/zswap/parameters/enabled",
                               detail="zswap.enabled = N",
                               command="cat /sys/module/zswap/parameters/enabled")],
            confidence=Confidence.MEASURED,
            recommendations=["zram swap provides the same benefit and is easier to enable; prefer it."],
            repair_ids=["memory.zram_swap"],
        ))

    if not findings:
        findings.append(Finding(
            id="memory.ok",
            title=f"Memory looks healthy ({avail_mb} MB of {total_mb} MB available)",
            category=Category.MEMORY, severity=Severity.OK,
            summary=f"{avail_pct}% of RAM is available and swap is configured ({swap_total_mb} MB).",
            evidence=mem_ev, confidence=Confidence.MEASURED))

    return result("memory", "Memory and swap", Category.MEMORY, findings, facts=facts)
