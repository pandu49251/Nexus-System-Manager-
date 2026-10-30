"""
nexus_doctor.checks.storage_health
==================================

Physical health of the storage device: S.M.A.R.T. data, kernel I/O errors,
filesystem consistency state, and whether the disk is being monitored.

Why this matters most on this laptop
------------------------------------
A 1 TB mechanical drive is the slowest component in the system and the only one
with moving parts that physically wear out.  Two very different problems hide
behind "my laptop is slow":

* the disk is *fine but simply slow* (rotational latency) - fixable by tuning;
* the disk is *failing* (reallocated/pending sectors, I/O errors) - a data-loss
  emergency that no amount of tuning will fix.

Distinguishing them is the main job of this module, so raw S.M.A.R.T. values
and kernel error lines are always shown verbatim as evidence.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..core import executil as ex
from ..core import privileges
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import (human_bytes, match_lines, result, uptime_text)

# S.M.A.R.T. attributes that directly indicate physical degradation.
CRITICAL_ATTRS = {
    "Reallocated_Sector_Ct": ("reallocated sectors",
                              "The drive has retired bad sectors by substituting spares. "
                              "This count only ever increases."),
    "Current_Pending_Sector": ("sectors waiting to be reallocated",
                               "These sectors could not be read. If a write to them fails, "
                               "the data is lost."),
    "Offline_Uncorrectable": ("uncorrectable sectors",
                              "Sectors that failed an offline scan and cannot be repaired."),
    "Reported_Uncorrect": ("errors reported to the host",
                           "Read or write commands that completed with an uncorrectable error."),
    "Command_Timeout": ("timed-out commands",
                        "Commands that the drive failed to complete in time, often a sign of "
                        "mechanical trouble."),
}
INFO_ATTRS = {
    "Power_On_Hours": "hours powered on",
    "Load_Cycle_Count": "head load/unload cycles",
    "Start_Stop_Count": "spindle start/stop cycles",
    "Temperature_Celsius": "degrees Celsius",
    "UDMA_CRC_Error_Count": "interface CRC errors",
    "Reallocated_Event_Count": "reallocation events",
    "Total_LBAs_Written": "LBAs written",
}

ATTR_LINE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+0x[0-9a-fA-F]+\s+(\d+|-)\s+(\d+|-)\s+(\d+|-)\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(.+)$")


def parse_smart_attributes(text: str) -> Dict[str, Dict[str, str]]:
    """Parse the ``smartctl -A`` attribute table into a name-keyed dict."""
    out: Dict[str, Dict[str, str]] = {}
    for line in (text or "").splitlines():
        m = ATTR_LINE.match(line)
        if not m:
            continue
        raw = m.group(9).strip()
        out[m.group(2)] = {
            "id": m.group(1),
            "value": m.group(3),
            "worst": m.group(4),
            "thresh": m.group(5),
            "type": m.group(6),
            "updated": m.group(7),
            "when_failed": m.group(8),
            "raw": raw,
            "raw_int": raw.split()[0].replace(",", "") if raw else "0",
        }
    return out


def parse_smart_info(text: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    keys = ("Model Number", "Device Model", "Serial Number", "Firmware Version",
            "User Capacity", "Sector Sizes", "Rotation Rate", "Device is",
            "SMART support is", "SMART overall-health self-assessment test result",
            "SMART Health Status", "ATA Version is", "SATA Version is",
            "Local Time is", "SMART is")
    for line in (text or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            if k in keys:
                info[k] = v.strip()
    return info


def _needs_root(res) -> bool:
    blob = (res.err or "") + (res.out or "")
    return bool(re.search(r"Permission denied|Operation not permitted|must be root|"
                          r"you need to be root|Access denied|Insufficient permission",
                          blob, re.I))


@register("storage_health", "Hard disk health (S.M.A.R.T.)", Category.STORAGE,
          priority=11, root_helpful=True,
          description="SMART data, bad sectors, I/O errors, filesystem consistency")
def check_storage_health(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}
    disks = f.physical_disks()
    facts["disks"] = disks

    if not disks:
        return result("storage_health", "Hard disk health (S.M.A.R.T.)", Category.STORAGE,
                      [Finding(id="storage.no_disks", title="No physical disks detected",
                               category=Category.STORAGE, severity=Severity.INFO,
                               summary="No physical block devices were found; SMART checks skipped.",
                               confidence=Confidence.DIRECT, manual=True)],
                      state="degraded", notes="no block devices")

    for disk in disks:
        name = disk["name"]
        dev = f"/dev/{name}"
        is_hdd = disk.get("rotational", False)
        label = disk.get("model") or dev
        facts[f"disk.{name}.rotational"] = is_hdd

        # ------------------------------------------------- mechanical disk
        if is_hdd:
            findings.append(Finding(
                id=f"storage.mechanical_{name}",
                title=f"{label} is a mechanical hard disk ({disk.get('size_gb', 0)} GB)",
                category=Category.STORAGE,
                severity=Severity.MEDIUM,
                summary=("The system disk spins at a fixed RPM and must physically move a "
                         "head to read data. Random access takes roughly 10 ms versus "
                         "under 0.1 ms on an SSD."),
                root_cause=("Rotational storage: every application launch, every shared "
                            "library and every icon is a separate seek. This is the dominant "
                            "hardware reason this laptop feels slow, and it interacts with "
                            "the 4 GB of RAM by making paging extremely expensive."),
                impact=("Slow boot, slow application start-up, and long freezes whenever "
                        "many small files are read at once (updates, indexing, browsing)."),
                evidence=[
                    Evidence(source=f"/sys/block/{name}/queue/rotational", detail="rotational = 1 (spinning disk)",
                             raw="1", command=f"cat /sys/block/{name}/queue/rotational"),
                    Evidence(source=f"/sys/block/{name}/device/model", detail=f"model = {label}",
                             command=f"cat /sys/block/{name}/device/model"),
                    Evidence(source=f"/sys/block/{name}/size",
                             detail=f"capacity = {disk.get('size_gb')} GB",
                             command=f"cat /sys/block/{name}/size"),
                ],
                confidence=Confidence.MEASURED,
                recommendations=[
                    "Replacing this drive with an SSD is by far the largest possible improvement "
                    "(roughly 5-10x faster application start-up).",
                    "Until then: keep free space above 20%, avoid heavy desktop search indexing, "
                    "and let the disk idle when it is busy.",
                ],
                manual=True,
                data={"device": dev, "rotational": True},
            ))

        # ------------------------------------------------------- SMART data
        smartctl = ex.find_tool("smartctl")
        if smartctl is None:
            findings.append(Finding(
                id=f"storage.smart_missing_{name}",
                title="Disk health cannot be verified: smartmontools is not installed",
                category=Category.STORAGE,
                severity=Severity.MEDIUM,
                summary=("S.M.A.R.T. is the drive's own health report. Without the "
                         "smartctl tool we cannot read it, so a failing disk would go "
                         "unnoticed until it stops working."),
                root_cause="The smartmontools package is not installed (it is optional on Linux Mint).",
                impact="No early warning of disk failure; silent data loss is possible.",
                evidence=[Evidence(source="PATH lookup", detail="smartctl: not found",
                                   command="command -v smartctl")],
                confidence=Confidence.MEASURED,
                needs_network=True,
                recommendations=[
                    "Install it with: sudo apt install smartmontools  (needs an internet connection)",
                    "Then re-run the scan to read this disk's health report.",
                ],
                manual=True,
            ))
            continue

        res = ex.run([smartctl, "-H", "-i", "-A", dev], timeout=25, root=True)
        if _needs_root(res) or (not res.ok and res.state in ("error",) and not res.out.strip()):
            findings.append(Finding(
                id=f"storage.smart_needs_root_{name}",
                title="Disk health could not be read (administrator rights required)",
                category=Category.STORAGE,
                severity=Severity.MEDIUM,
                summary=("Reading S.M.A.R.T. data directly from the drive requires root. "
                         "Run the scan with administrator rights to see this disk's health."),
                root_cause="smartctl needs CAP_SYS_RAWIO / root to query the ATA device.",
                impact="Unknown disk health - a failing disk would not be detected.",
                evidence=[Evidence(source=" ".join(res.argv),
                                   detail=(res.err.strip() or res.detail or "permission denied")[:200],
                                   command=f"sudo smartctl -H -i -A {dev}", root_required=True)],
                confidence=Confidence.DIRECT,
                needs_root=True,
                recommendations=[f"Re-run with: sudo nexus-doctor --cli --scan",
                                 f"or check manually: sudo smartctl -H -A {dev}"],
                manual=True,
            ))
            continue
        if not res.ok and not res.out.strip():
            findings.append(Finding(
                id=f"storage.smart_unreadable_{name}",
                title=f"S.M.A.R.T. could not be read from {dev}",
                category=Category.STORAGE,
                severity=Severity.LOW,
                summary=f"smartctl exited with status {res.rc} and produced no data.",
                root_cause=res.err.strip()[:200] or "device did not answer the SMART query "
                                                    "(some USB bridges and virtual disks do not support it)",
                evidence=[Evidence(source=" ".join(res.argv),
                                   detail=(res.err.strip() or "no output")[:200],
                                   command=f"smartctl -H -i -A {dev}")],
                confidence=Confidence.DIRECT, manual=True,
            ))
            continue

        info = parse_smart_info(res.out)
        attrs = parse_smart_attributes(res.out)
        facts[f"disk.{name}.smart"] = {"info": info, "attributes": attrs}

        health = (info.get("SMART overall-health self-assessment test result")
                  or info.get("SMART Health Status") or "")
        facts[f"disk.{name}.health"] = health

        ev_info = [Evidence(source=f"smartctl -i {dev}",
                            detail="; ".join(f"{k}: {v}" for k, v in info.items() if k in
                                             ("Device Model", "Model Number", "Serial Number",
                                              "Firmware Version", "User Capacity",
                                              "Rotation Rate", "SMART support is")) or "no info block",
                            raw=res.out[:1500],
                            command=f"sudo smartctl -i {dev}", root_required=True)]

        if re.search(r"FAILED", health, re.I):
            findings.append(Finding(
                id=f"storage.smart_failed_{name}",
                title=f"SMART reports the disk is FAILING: {label}",
                category=Category.STORAGE,
                severity=Severity.CRITICAL,
                summary=(f"The drive's own self-test reports '{health}'. It has detected that "
                         f"it can no longer reliably store data."),
                root_cause="Physical failure of the storage medium or its mechanics.",
                impact="Data loss is likely and may already be occurring. Back up immediately.",
                evidence=ev_info + [
                    Evidence(source=f"smartctl -H {dev}", detail=f"health: {health}",
                             command=f"sudo smartctl -H {dev}", root_required=True)],
                confidence=Confidence.DIRECT,
                recommendations=[
                    "Back up your personal files NOW to an external drive or cloud storage.",
                    "Do not run disk-intensive tasks (updates, indexing) until backed up.",
                    "Replace the drive; a failing mechanical disk does not recover.",
                ],
                manual=True, needs_root=True,
            ))
        elif health:
            findings.append(Finding(
                id=f"storage.smart_ok_{name}",
                title=f"SMART self-test passed for {label}",
                category=Category.STORAGE, severity=Severity.OK,
                summary=f"The drive reports: {health}.",
                evidence=ev_info, confidence=Confidence.DIRECT, needs_root=True))

        # Critical counters
        for attr, (human, why) in CRITICAL_ATTRS.items():
            if attr not in attrs:
                continue
            a = attrs[attr]
            try:
                raw_val = int(re.sub(r"[^\d]", "", a["raw_int"]) or 0)
            except ValueError:
                continue
            if raw_val <= 0:
                continue
            sev = Severity.CRITICAL if raw_val >= 16 else (
                Severity.HIGH if raw_val >= 1 else Severity.MEDIUM)
            findings.append(Finding(
                id=f"storage.{attr.lower()}_{name}",
                title=f"{label}: {raw_val} {human} reported by SMART",
                category=Category.STORAGE,
                severity=sev,
                summary=(f"SMART attribute {a['id']} ({attr}) has a raw value of {raw_val}. "
                         f"{why}"),
                root_cause=("Physical degradation of the magnetic medium or the head/actuator "
                            "assembly. These counters never decrease."),
                impact=("Reads from affected sectors are slow (the drive retries) or fail "
                        "outright; data in those sectors is at risk."),
                evidence=[
                    Evidence(source=f"smartctl -A {dev}",
                             detail=f"{attr}: raw={a['raw']} normalised={a['value']} "
                                    f"threshold={a['thresh']} when_failed={a['when_failed']}",
                             raw=_attr_line(res.out, attr),
                             command=f"sudo smartctl -A {dev}", root_required=True)],
                confidence=Confidence.DIRECT,
                needs_root=True,
                recommendations=[
                    "Back up important files immediately.",
                    "Run a full surface test: sudo smartctl -t long /dev/" + name +
                    " (takes an hour or more on 1 TB).",
                    "Plan to replace the drive if the number grows.",
                ],
                manual=True,
                data={"attribute": attr, "raw": raw_val},
            ))

        # CRC errors => cable/controller, not the platter (very common on laptops)
        crc = attrs.get("UDMA_CRC_Error_Count")
        if crc:
            try:
                crc_val = int(re.sub(r"[^\d]", "", crc["raw_int"]) or 0)
            except ValueError:
                crc_val = 0
            if crc_val > 0:
                findings.append(Finding(
                    id=f"storage.crc_errors_{name}",
                    title=f"{label}: {crc_val} interface CRC errors (cable / connection)",
                    category=Category.STORAGE,
                    severity=Severity.MEDIUM if crc_val < 100 else Severity.HIGH,
                    summary=("Data was corrupted in transit between the disk and the "
                             "controller. This is usually the SATA cable or its connector "
                             "on the motherboard, not the disk surface."),
                    root_cause=("Signal integrity problem on the SATA link; inside a laptop "
                                "this is typically a loose or worn connector."),
                    impact=("The link drops to a slower speed and retries, which makes the "
                            "whole system stutter."),
                    evidence=[Evidence(source=f"smartctl -A {dev}",
                                       detail=f"UDMA_CRC_Error_Count raw = {crc['raw']}",
                                       raw=_attr_line(res.out, "UDMA_CRC_Error_Count"),
                                       command=f"sudo smartctl -A {dev}", root_required=True)],
                    confidence=Confidence.DIRECT,
                    recommendations=[
                        "If the count keeps rising, have the SATA connector reseated or the cable replaced.",
                        "Back up data while the drive is still readable.",
                    ],
                    manual=True, needs_root=True,
                ))

        # Temperature
        temp = attrs.get("Temperature_Celsius") or attrs.get("Airflow_Temperature_Cel")
        if temp:
            try:
                tval = int(re.sub(r"[^\d]", "", temp["raw_int"]) or 0)
            except ValueError:
                tval = 0
            facts[f"disk.{name}.temp_c"] = tval
            if tval >= 55:
                findings.append(Finding(
                    id=f"storage.hot_{name}",
                    title=f"Hard disk is running hot ({tval} °C)",
                    category=Category.STORAGE,
                    severity=Severity.HIGH if tval >= 60 else Severity.MEDIUM,
                    summary=f"The drive reports {tval} °C. Mechanical disks age quickly above ~50 °C.",
                    root_cause="Insufficient airflow, dust in the fan/heatsink, or sustained heavy I/O.",
                    impact="Shortened disk life and thermal slowdown of the whole laptop.",
                    evidence=[Evidence(source=f"smartctl -A {dev}",
                                       detail=f"Temperature_Celsius raw = {temp['raw']}",
                                       raw=_attr_line(res.out, "Temperature_Celsius"),
                                       command=f"sudo smartctl -A {dev}", root_required=True)],
                    confidence=Confidence.DIRECT,
                    recommendations=[
                        "Clean the fan and vents (compressed air).",
                        "Make sure the laptop sits on a hard surface, not a bed or cushion.",
                        "Reduce background disk activity (see the search-indexer findings).",
                    ],
                    manual=True, needs_root=True,
                ))

        # Power-on hours / wear context
        poh = attrs.get("Power_On_Hours")
        if poh:
            try:
                hours = int(re.sub(r"[^\d]", "", poh["raw_int"]) or 0)
            except ValueError:
                hours = 0
            facts[f"disk.{name}.power_on_hours"] = hours
            if hours >= 20000:
                findings.append(Finding(
                    id=f"storage.aged_{name}",
                    title=f"Hard disk has been powered on for {hours:,} hours",
                    category=Category.STORAGE,
                    severity=Severity.LOW if hours < 35000 else Severity.MEDIUM,
                    summary=(f"{hours:,} hours is roughly {hours // 8766} years of continuous "
                             f"use. Mechanical wear accumulates even when SMART passes."),
                    root_cause="Age and accumulated mechanical wear.",
                    evidence=[Evidence(source=f"smartctl -A {dev}",
                                       detail=f"Power_On_Hours raw = {poh['raw']}",
                                       raw=_attr_line(res.out, "Power_On_Hours"),
                                       command=f"sudo smartctl -A {dev}", root_required=True)],
                    confidence=Confidence.DIRECT,
                    recommendations=["Keep backups current; consider replacing with an SSD proactively."],
                    manual=True,
                ))

        # Head parking (Load_Cycle_Count) -- classic laptop-HDD wear
        lcc = attrs.get("Load_Cycle_Count")
        if lcc:
            try:
                cycles = int(re.sub(r"[^\d]", "", lcc["raw_int"]) or 0)
            except ValueError:
                cycles = 0
            facts[f"disk.{name}.load_cycles"] = cycles
            if cycles >= 300000:
                findings.append(Finding(
                    id=f"storage.load_cycles_{name}",
                    title=f"Hard disk heads have parked {cycles:,} times",
                    category=Category.STORAGE,
                    severity=Severity.MEDIUM,
                    summary=("The head assembly has unloaded itself %s times. Laptop firmware "
                             "often parks the heads very aggressively to save power, which "
                             "wears the mechanism." % f"{cycles:,}"),
                    root_cause="Aggressive head-parking (APM) firmware policy.",
                    impact="Audible clicking, spin-up delays, and reduced drive lifespan.",
                    evidence=[Evidence(source=f"smartctl -A {dev}",
                                       detail=f"Load_Cycle_Count raw = {lcc['raw']}",
                                       raw=_attr_line(res.out, "Load_Cycle_Count"),
                                       command=f"sudo smartctl -A {dev}", root_required=True)],
                    confidence=Confidence.DIRECT,
                    recommendations=[
                        "Check the idle policy: sudo hdparm -B /dev/" + name,
                        "A value of 254 keeps heads off the ramp at the cost of some power.",
                    ],
                    manual=True, needs_root=True,
                ))

    # -------------------------------------------------- kernel I/O errors
    logs = ctx.shared_get("log.lines")
    if logs is None:
        from .common import kernel_messages
        logs = kernel_messages(400)
        ctx.share("log.lines", logs)

    io_patterns = [
        r"I/O error, dev ",
        r"buffer I/O error",
        r"EXT4-fs error",
        r"ata\d+(\.\d+)?: .*(exception Emask|status: \{ )",
        r"hard resetting link",
        r"failed command: (READ|WRITE) FPDMA QUEUED",
        r"blk_update_request: I/O error",
        r"critical medium error",
        r"Remounting filesystem read-only",
        r"EXT4-fs \(\w+\): Remounting filesystem read-only",
    ]
    hits = match_lines(logs, io_patterns, limit=8)
    if hits:
        crit = any(re.search(r"Remounting filesystem read-only|EXT4-fs error|critical medium",
                             line, re.I) for _p, line in hits)
        findings.append(Finding(
            id="storage.io_errors",
            title=f"The kernel logged {len(hits)} disk I/O error(s) during this session",
            category=Category.STORAGE,
            severity=Severity.CRITICAL if crit else Severity.HIGH,
            summary=("The operating system itself reported that it could not read from or "
                     "write to the disk. This is not a performance problem - it means data "
                     "transfers are failing."),
            root_cause=("Failing sectors, a faulty SATA link, or (rarely) a filesystem bug. "
                        "If the filesystem has been remounted read-only, the kernel is "
                        "protecting the data on a device it no longer trusts."),
            impact="File corruption, failed saves, and sudden read-only filesystems.",
            evidence=[Evidence(source="kernel log", detail=line[:200], raw=line,
                               command="journalctl -k -b | grep -iE 'i/o error|ata|ext4'")
                      for _p, line in hits],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Back up your files immediately.",
                "Check the filesystem from a live USB: sudo fsck -f /dev/<root-partition>",
                "Compare against the SMART report above to confirm physical failure.",
            ],
            manual=True,
            data={"count": len(hits)},
        ))

    # --------------------------------------------------- fsck / filesystem
    root_dev = f.root_device()
    root_mnt = f.root_mount()
    facts["root_device"] = root_dev
    facts["root_mount"] = root_mnt
    if root_mnt.get("fstype", "").startswith("ext") and root_dev:
        part = root_mnt.get("device", "")
        r = ex.run(["tune2fs", "-l", part], timeout=15, root=True)
        if r.ok:
            kv = {}
            for line in r.lines:
                if ":" in line:
                    k, _, v = line.partition(":")
                    kv[k.strip()] = v.strip()
            facts["fsck"] = {k: kv.get(k) for k in
                             ("Filesystem state", "Last checked", "Mount count",
                              "Maximum mount count", "Next check after", "Errors behavior")}
            try:
                mc = int(kv.get("Mount count", "0") or 0)
                mx = int(kv.get("Maximum mount count", "0") or 0)
            except ValueError:
                mc = mx = 0
            if mx > 0 and mc >= mx:
                findings.append(Finding(
                    id="storage.fsck_pending",
                    title="A full filesystem check is due at the next boot",
                    category=Category.STORAGE,
                    severity=Severity.LOW,
                    summary=(f"The root filesystem has been mounted {mc} times, which reaches "
                             f"its check interval of {mx}. The next boot will run fsck."),
                    root_cause="ext4 periodic check interval reached.",
                    impact="One slow boot (a full fsck on 1 TB can take several minutes) - "
                           "this is expected, not a fault.",
                    evidence=[Evidence(source=f"tune2fs -l {part}",
                                       detail=f"Mount count: {mc}, Maximum mount count: {mx}",
                                       raw=r.out[:800], command=f"sudo tune2fs -l {part}",
                                       root_required=True)],
                    confidence=Confidence.DIRECT,
                    recommendations=["Let it finish - interrupting a filesystem check is dangerous."],
                    manual=True,
                ))
            if kv.get("Filesystem state", "").startswith("clean with errors"):
                findings.append(Finding(
                    id="storage.fs_errors",
                    title="Filesystem metadata contains errors",
                    category=Category.STORAGE,
                    severity=Severity.HIGH,
                    summary="tune2fs reports the filesystem is 'clean with errors'.",
                    root_cause="Previous corruption, possibly from the disk errors listed above.",
                    evidence=[Evidence(source=f"tune2fs -l {part}",
                                       detail=f"Filesystem state: {kv.get('Filesystem state')}",
                                       command=f"sudo tune2fs -l {part}", root_required=True)],
                    confidence=Confidence.DIRECT,
                    recommendations=[f"Run: sudo fsck -f {part}  (from a live USB if it is the root filesystem)"],
                    manual=True,
                ))

    # read-only remount check from mount options
    if "ro," in root_mnt.get("options", "") or root_mnt.get("options", "").endswith(",ro"):
        findings.append(Finding(
            id="storage.root_readonly",
            title="The root filesystem is mounted read-only",
            category=Category.STORAGE,
            severity=Severity.CRITICAL,
            summary="Nothing can be saved. The kernel remounted the filesystem read-only to protect it.",
            root_cause="A disk or filesystem error triggered the 'errors=remount-ro' policy.",
            impact="No updates, no saved documents, applications may fail to start.",
            evidence=[Evidence(source="/proc/mounts",
                               detail=f"{root_mnt.get('device')} on / options: {root_mnt.get('options')}",
                               command="cat /proc/mounts")],
            confidence=Confidence.MEASURED,
            recommendations=[f"Back up immediately, then run fsck from a live USB: sudo fsck -f {root_mnt.get('device')}",
                             "If the disk is failing, replace it."],
            manual=True,
        ))

    # ---------------------------------------------------- smartd monitoring
    if ex.find_tool("smartctl"):
        r = ex.run(["systemctl", "is-enabled", "smartd"], timeout=8)
        enabled = r.ok and r.first.strip() in ("enabled", "enabled-runtime")
        facts["smartd_enabled"] = enabled
        if not enabled:
            findings.append(Finding(
                id="storage.smartd_off",
                title="No automatic disk-health monitoring is running",
                category=Category.STORAGE,
                severity=Severity.LOW,
                summary=("The smartd daemon is not enabled, so nothing is watching the disk "
                         "between scans and a slow failure could go unnoticed for months."),
                root_cause="smartd service is not enabled (smartmontools ships it disabled by default).",
                impact="Failure warnings arrive too late to back up comfortably.",
                evidence=[Evidence(source="systemctl is-enabled smartd",
                                   detail=f"result: {r.first.strip() or 'not found'}",
                                   command="systemctl is-enabled smartd")],
                confidence=Confidence.DIRECT,
                recommendations=["Enable smartd so failures are reported as they happen."],
                repair_ids=["storage.enable_smartd"],
            ))

    return result("storage_health", "Hard disk health (S.M.A.R.T.)", Category.STORAGE,
                  findings, facts=facts)


def _attr_line(text: str, attr: str) -> str:
    for line in (text or "").splitlines():
        if attr in line:
            return line.strip()
    return ""
