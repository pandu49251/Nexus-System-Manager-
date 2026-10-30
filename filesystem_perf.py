"""
nexus_doctor.checks.filesystem_perf
===================================

Direct measurement of how fast the disk actually is (deep scan only).

Everything else in this application infers performance from configuration.
This module measures it, because "the disk is just slow" and "the disk is
broken" need different responses, and only a measurement separates them.

Two numbers matter, and they are very different on a mechanical disk:

* **Sustained write throughput** (with ``fsync``, so the page cache cannot
  flatter the result) - a healthy 5400 rpm laptop drive manages 60-110 MB/s.
* **Random 4 KB read rate** - the number that governs how fast applications
  *start*.  A mechanical disk performs roughly 80-150 of these per second
  versus tens of thousands on an SSD.  This single figure explains why opening
  a browser takes ten seconds on a laptop that "should be fast enough".

Safety: the test writes a temporary file into the user's own cache directory,
fsyncs it, reads it back and deletes it.  It never touches user data, refuses
to run with less than 800 MB free, and is skipped entirely in sandbox mode.
"""

from __future__ import annotations

import os
import random
import time
from typing import Dict, List, Optional

from ..core import executil as ex
from ..core import privileges
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import human_bytes, result
from .storage_space import usage

TEST_FILE = ".nexus-system-doctor-benchmark.tmp"
SIZE_MB = 64
RANDOM_READS = 256
MIN_FREE_BYTES = 800 * 1024 * 1024


def benchmark(directory: str, size_mb: int = SIZE_MB) -> Optional[Dict[str, float]]:
    """Write, fsync, re-read and randomly re-read a temporary file.

    All file access goes through ``executil`` so that the benchmark is covered
    by the same redirection and write protection as everything else; a
    benchmark that could write anywhere would be the most dangerous code in
    the program.
    """
    path = os.path.join(directory, TEST_FILE)
    block = os.urandom(1024 * 1024)
    ex.remove(path)

    # ---- sustained write, flushed to the physical device -----------------
    t0 = time.monotonic()
    if not ex.write_bytes(path, block * size_mb, sync=True):
        return {"error": "could not create the test file"}
    write_s = time.monotonic() - t0

    # ---- random 4 KiB reads (what an application launch actually does) ---
    size = ex.file_size(path) or size_mb * 1024 * 1024
    rnd = random.Random(1234)
    offsets = [rnd.randrange(0, max(1, size - 4096)) for _ in range(RANDOM_READS)]
    try:
        t0 = time.monotonic()
        got = ex.read_at(path, offsets, 4096)
        rnd_s = time.monotonic() - t0
    finally:
        ex.remove(path)
    if not got:
        return {"error": "could not read the test file back"}

    # ---- sequential read -------------------------------------------------
    t0 = time.monotonic()
    ex.read_at(path, [i * 1024 * 1024 for i in range(size_mb)], 1024 * 1024)
    read_s = time.monotonic() - t0

    return {
        "write_mb_s": round(size_mb / write_s, 1) if write_s > 0 else 0.0,
        "read_mb_s": round(size_mb / read_s, 1) if read_s > 0 else 0.0,
        "random_iops": round(RANDOM_READS / rnd_s, 1) if rnd_s > 0 else 0.0,
        "random_ms": round(rnd_s * 1000.0 / RANDOM_READS, 2) if rnd_s > 0 else 0.0,
        "size_mb": size_mb,
        "reads": RANDOM_READS,
    }


@register("filesystem_perf", "Measured disk speed", Category.STORAGE, priority=70,
          deep=True, description="Writes and reads a temporary file to measure real disk speed")
def check_filesystem_perf(ctx: ScanContext):
    f = ctx.f
    facts: Dict[str, object] = {}
    findings: List[Finding] = []

    if ex.SANDBOX:
        return result("filesystem_perf", "Measured disk speed", Category.STORAGE, [],
                      state="skipped", notes="sandbox mode: benchmark disabled")

    home = privileges.user_home()
    target = home if os.access(home, os.W_OK) else "/tmp"
    space = usage(target if target != "/tmp" else "/tmp")
    free = space["avail"] if space else 0
    if free < MIN_FREE_BYTES:
        return result("filesystem_perf", "Measured disk speed", Category.STORAGE, [],
                      state="skipped",
                      notes=f"only {human_bytes(free)} free: not enough headroom to benchmark safely")

    res = benchmark(target)
    if not res or "error" in res:
        return result("filesystem_perf", "Measured disk speed", Category.STORAGE, [],
                      state="failed", notes=f"benchmark failed: {(res or {}).get('error')}")

    facts["benchmark"] = res
    facts["benchmark_dir"] = target
    rotational = f.is_hdd(f.root_device())

    ev = [Evidence(source=f"measured write of {res['size_mb']} MB with fsync to {target}",
                   detail=f"sustained write {res['write_mb_s']} MB/s (data flushed to the device)",
                   command="# Nexus System Doctor disk benchmark"),
          Evidence(source=f"measured sequential re-read of {res['size_mb']} MB",
                   detail=f"{res['read_mb_s']} MB/s (may be served partly from the page cache)",
                   command="# Nexus System Doctor disk benchmark"),
          Evidence(source=f"{res['reads']} random 4 KiB reads",
                   detail=f"{res['random_iops']} IOPS, {res['random_ms']} ms per read",
                   command="# Nexus System Doctor disk benchmark")]

    # ------------------------------------------------ random read verdict
    if rotational and res["random_iops"] < 300:
        findings.append(Finding(
            id="perf.random_slow",
            title=f"Random reads are very slow: {res['random_iops']} per second ({res['random_ms']} ms each)",
            category=Category.STORAGE,
            severity=Severity.HIGH if res["random_iops"] < 150 else Severity.MEDIUM,
            summary=(f"Reading {res['reads']} scattered 4 KB blocks took "
                     f"{res['random_ms']} ms each. A mechanical disk must physically move "
                     f"its head for every one of them."),
            root_cause=("Rotational latency plus seek time. Opening an application reads "
                        "hundreds of scattered small files (shared libraries, icons, "
                        "configuration), so start-up time is dominated by this number."),
            impact=("Application start-up measured in seconds, stuttering when several "
                    "things load at once, long boot times."),
            evidence=ev,
            confidence=Confidence.MEASURED,
            recommendations=[
                "Keep 20% of the disk free so the allocator can place files contiguously.",
                "Disable background indexers (see the Services check) - they compete directly "
                "for the same random I/O.",
                "Only an SSD changes this number by an order of magnitude; it is the single "
                "most effective upgrade for this machine.",
            ],
            manual=True,
            repair_ids=["services.disable_indexers"],
            data={"iops": res["random_iops"]},
        ))

    # ------------------------------------------------- sustained write
    if res["write_mb_s"] < 40:
        findings.append(Finding(
            id="perf.write_slow",
            title=f"Sustained write speed is low: {res['write_mb_s']} MB/s",
            category=Category.STORAGE, severity=Severity.MEDIUM,
            summary=(f"Writing {res['size_mb']} MB and flushing it to the device achieved "
                     f"only {res['write_mb_s']} MB/s. A healthy laptop drive writes at "
                     f"60-110 MB/s."),
            root_cause=("Either the drive is heavily fragmented / nearly full, it is "
                        "re-writing sectors that failed (see the SMART check), or it is "
                        "thermally throttling."),
            impact="Saving large files, installing updates and copying media are slow.",
            evidence=ev, confidence=Confidence.MEASURED,
            recommendations=[
                "Check free space and the SMART report above.",
                "Large sustained writes slow down when the disk is nearly full.",
            ],
            manual=True,
            data={"mb_s": res["write_mb_s"]},
        ))

    if not findings:
        findings.append(Finding(
            id="perf.ok",
            title=f"Disk measures {res['write_mb_s']} MB/s write, {res['random_iops']} random IOPS",
            category=Category.STORAGE, severity=Severity.OK,
            summary="Measured performance is within the normal range for this type of drive.",
            evidence=ev, confidence=Confidence.MEASURED,
            data=res))

    return result("filesystem_perf", "Measured disk speed", Category.STORAGE, findings,
                  facts=facts)
