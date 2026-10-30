"""
nexus_doctor.checks.cpu_thermal
===============================

Processor load, frequency scaling and temperature.

The key question this module answers is: **when the machine feels slow, is the
CPU working hard, waiting on the disk, or being held back by heat?**

Those three states look identical to the user but have completely different
fixes, so we measure them separately:

* high ``iowait``  -> the disk is the bottleneck (see the storage checks);
* high CPU by one process -> a runaway application;
* high temperature / low frequency -> thermal throttling, a hardware problem
  that software cannot fix.
"""

from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Optional, Tuple

from ..core import executil as ex
from ..core import privileges
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import (cpu_usage_sample, human_bytes, match_lines, pct, processes,
                     result, top_memory_procs)

THERMAL_BASE = "/sys/class/thermal"
SENSOR_RE = re.compile(r"^(?P<name>[^:]+):\s+(?P<value>[+-]?\d+\.?\d*)\s*°?C"
                       r"(?:\s+\(.*?(?:crit|critical)\s*=\s*[+-]?(?P<crit>\d+\.?\d*)°?C.*?\))?",
                       re.I)


def thermal_zones() -> List[Dict[str, object]]:
    zones: List[Dict[str, object]] = []
    for z in ex.listdir(THERMAL_BASE):
        if not z.startswith("thermal_zone"):
            continue
        base = f"{THERMAL_BASE}/{z}"
        raw = ex.read_text(f"{base}/temp")
        try:
            temp = int((raw or "0").strip()) / 1000.0
        except ValueError:
            continue
        ztype = (ex.read_text(f"{base}/type") or "unknown").strip()
        trip = (ex.read_text(f"{base}/trip_point_0_temp") or "").strip()
        policy = (ex.read_text(f"{base}/policy") or "").strip()
        zones.append({"zone": z, "type": ztype, "temp_c": round(temp, 1),
                      "trip_point_0": int(trip) / 1000.0 if trip.isdigit() else None,
                      "policy": policy})
    return zones


def parse_sensors(text: str) -> List[Dict[str, object]]:
    """Parse ``sensors`` output into chip/feature/temperature records."""
    out: List[Dict[str, object]] = []
    chip = ""
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if not line.startswith(" ") and not line.startswith("\t") and ":" not in line:
            chip = line.strip()
            continue
        if line.strip().startswith("Adapter:"):
            continue
        m = SENSOR_RE.match(line.strip())
        if m:
            try:
                val = float(m.group("value"))
            except ValueError:
                continue
            crit = float(m.group("crit")) if m.group("crit") else None
            out.append({"chip": chip, "feature": m.group("name").strip(),
                        "temp_c": val, "critical_c": crit})
    return out


def iowait_percent(interval: float = 1.0) -> Optional[float]:
    """Measure the fraction of time the CPUs spent waiting on I/O, right now."""
    def read_cpu() -> Optional[Tuple[int, int]]:
        line = ex.read_text("/proc/stat")
        if not line:
            return None
        for l in line.splitlines():
            if l.startswith("cpu "):
                parts = l.split()
                try:
                    total = sum(int(x) for x in parts[1:8])
                    iowait = int(parts[5]) if len(parts) > 5 else 0
                except ValueError:
                    return None
                return total, iowait
        return None

    a = read_cpu()
    if not a:
        return None
    time.sleep(interval)
    b = read_cpu()
    if not b:
        return None
    d_total = b[0] - a[0]
    d_io = b[1] - a[1]
    if d_total <= 0:
        return None
    return round(d_io * 100.0 / d_total, 1)


def cpu_frequencies() -> Tuple[List[int], Optional[int], Optional[int]]:
    """(current freqs kHz per core, max kHz, min kHz)."""
    cur: List[int] = []
    mx = mn = None
    for entry in ex.listdir("/sys/devices/system/cpu"):
        if not re.fullmatch(r"cpu\d+", entry):
            continue
        base = f"/sys/devices/system/cpu/{entry}/cpufreq"
        v = ex.read_text(f"{base}/scaling_cur_freq")
        if v and v.strip().isdigit():
            cur.append(int(v.strip()))
        if mx is None:
            v = ex.read_text(f"{base}/scaling_max_freq")
            if v and v.strip().isdigit():
                mx = int(v.strip())
            v = ex.read_text(f"{base}/cpuinfo_min_freq")
            if v and v.strip().isdigit():
                mn = int(v.strip())
    return cur, mx, mn


@register("cpu_thermal", "Processor, load and temperature", Category.CPU, priority=20,
          description="CPU load, iowait, frequency scaling, thermal throttling")
def check_cpu_thermal(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}

    cores = max(1, f.cpu_cores)
    threads = max(1, f.cpu_threads)
    facts.update({"cores": cores, "threads": threads, "model": f.cpu_model,
                  "governor": f.cpu_governor, "driver": f.cpu_driver})

    # ------------------------------------------------------------- load
    load1 = f.loadavg[0] if f.loadavg else 0.0
    load5 = f.loadavg[1] if len(f.loadavg) > 1 else 0.0
    facts["load1"] = load1
    facts["load5"] = load5
    if load1 > max(2.0, cores * 1.5):
        procs = processes()
        sample = cpu_usage_sample(procs, interval=0.5, n=5)
        hogs = [f"{p.name} {pctv:.0f}%" for p, pctv in sample if pctv > 15]
        findings.append(Finding(
            id="cpu.load_high",
            title=f"System load is {load1:.2f} on {cores} core(s)",
            category=Category.CPU,
            severity=Severity.HIGH if load1 > cores * 3 else Severity.MEDIUM,
            summary=(f"A load average of {load1:.2f} means about {load1:.1f} processes are "
                     f"competing for {cores} core(s). Work is queueing up."),
            root_cause=("Sustained demand exceeds what the CPU can retire. On a dual-core AMD "
                        "processor there is very little headroom, so one busy task is enough "
                        "to make everything else feel sluggish."),
            impact="Delayed response to clicks and keystrokes.",
            evidence=[
                Evidence(source="/proc/loadavg",
                         detail=f"1 min {load1:.2f}, 5 min {load5:.2f} on {threads} thread(s)",
                         raw=(ex.read_text("/proc/loadavg") or "").strip(),
                         command="cat /proc/loadavg"),
                Evidence(source="/proc/<pid>/stat (0.5 s sample)",
                         detail="Busiest processes: " + (", ".join(hogs) if hogs
                                                         else "none above 15% of a core"),
                         command="top -b -n1")],
            confidence=Confidence.MEASURED,
            recommendations=["Close or restart the busiest application listed above.",
                             "Check the startup applications found by the Services & startup check."],
            data={"load1": load1},
        ))

    # ----------------------------------------------------------- iowait
    iowait = iowait_percent(1.0)
    facts["iowait_pct"] = iowait
    if iowait is not None and iowait >= 12.0:
        findings.append(Finding(
            id="cpu.iowait_high",
            title=f"The CPU is idle {iowait}% of the time waiting for the disk",
            category=Category.CPU,
            severity=Severity.HIGH if iowait >= 25 else Severity.MEDIUM,
            summary=(f"In a 1-second measurement, {iowait}% of CPU time was spent blocked on "
                     f"I/O. The processor is not the bottleneck - the storage device is."),
            root_cause=("Processes are waiting on a mechanical hard disk. A 5400 rpm drive "
                        "services roughly 100 random requests per second, while an SSD does "
                        "tens of thousands; everything queues behind the disk."),
            impact=("The machine appears frozen while the disk light is on, even though the "
                    "CPU is mostly idle."),
            evidence=[Evidence(source="/proc/stat (1 s delta)",
                               detail=f"iowait = {iowait}% of CPU time",
                               command="cat /proc/stat; sleep 1; cat /proc/stat")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "Identify what is reading/writing (see the Services & startup check - desktop "
                "search indexers are the most common cause).",
                "Reduce paging pressure: enable zram and lower vm.swappiness.",
                "An SSD eliminates this class of problem entirely.",
            ],
            repair_ids=["memory.zram_swap", "services.disable_indexers"],
            data={"iowait_pct": iowait},
        ))

    # ------------------------------------------------------ governor
    if f.cpu_governor in ("powersave", "conservative"):
        findings.append(Finding(
            id="cpu.governor_low",
            title=f"CPU frequency governor is '{f.cpu_governor}'",
            category=Category.CPU,
            severity=Severity.MEDIUM if f.cpu_governor == "powersave" else Severity.LOW,
            summary=(f"The scaling governor '{f.cpu_governor}' keeps the processor at its "
                     f"lowest frequency. Everything runs slower than the hardware is capable of."),
            root_cause=("Either a power-saving profile is active, or the cpufreq driver "
                        "(%s) did not pick a demand-based governor such as schedutil." %
                        (f.cpu_driver or "unknown")),
            impact="Uniformly sluggish response, even for simple tasks.",
            evidence=[Evidence(source="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                               detail=f"scaling_governor = {f.cpu_governor}, driver = {f.cpu_driver}",
                               command="cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")],
            confidence=Confidence.MEASURED,
            recommendations=["Use the 'schedutil' (or 'ondemand') governor so frequency rises with demand."],
            repair_ids=["cpu.governor"],
            data={"governor": f.cpu_governor},
        ))
    elif not f.cpu_governor:
        findings.append(Finding(
            id="cpu.no_cpufreq",
            title="CPU frequency scaling is not exposed by this kernel",
            category=Category.CPU, severity=Severity.INFO,
            summary="No scaling_governor was found, so frequency cannot be measured or tuned.",
            root_cause="cpufreq driver not loaded (common inside virtual machines and containers).",
            evidence=[Evidence(source="/sys/devices/system/cpu/cpu0/cpufreq",
                               detail="directory not present",
                               command="ls /sys/devices/system/cpu/cpu0/cpufreq")],
            confidence=Confidence.DIRECT, manual=True))

    # ---------------------------------------------------- temperature
    zones = thermal_zones()
    sensors_out = ex.run(["sensors"], timeout=10) if ex.have_tool("sensors") else None
    sensor_records = parse_sensors(sensors_out.out) if (sensors_out and sensors_out.ok) else []
    facts["thermal_zones"] = zones
    facts["sensors"] = sensor_records[:20]

    hottest: Optional[Tuple[str, float]] = None
    temp_evidence: List[Evidence] = []
    if zones:
        for z in zones:
            temp_evidence.append(Evidence(
                source=f"/sys/class/thermal/{z['zone']}/temp",
                detail=f"{z['type']}: {z['temp_c']} °C" +
                       (f" (trip point {z['trip_point_0']} °C)" if z.get("trip_point_0") else ""),
                command=f"cat /sys/class/thermal/{z['zone']}/temp"))
        hottest = max(((str(z["type"]), float(z["temp_c"])) for z in zones),
                      key=lambda t: t[1])
    if sensor_records:
        best = max(sensor_records, key=lambda r: float(r["temp_c"]))
        temp_evidence.append(Evidence(
            source="sensors",
            detail="; ".join(f"{r['feature']} {r['temp_c']}°C" for r in sensor_records[:6]),
            raw=(sensors_out.out[:1200] if sensors_out else ""), command="sensors"))
        if hottest is None or float(best["temp_c"]) > hottest[1]:
            hottest = (str(best["feature"]), float(best["temp_c"]))

    if hottest:
        facts["hottest_c"] = hottest[1]
        if hottest[1] >= 90:
            sev = Severity.CRITICAL
        elif hottest[1] >= 80:
            sev = Severity.HIGH
        elif hottest[1] >= 70:
            sev = Severity.MEDIUM
        else:
            sev = None
        if sev is not None:
            findings.append(Finding(
                id="cpu.thermal_hot",
                title=f"{hottest[0]} is running at {hottest[1]:.0f} °C",
                category=Category.THERMAL,
                severity=sev,
                summary=(f"The hottest sensor reads {hottest[1]:.0f} °C. Modern AMD mobile "
                         f"processors begin protecting themselves around 95-100 °C by cutting "
                         f"clock speed."),
                root_cause=("Heat is not being removed fast enough: dust blocking the fan and "
                            "heatsink fins is the usual cause on a laptop of this age, followed "
                            "by dried-out thermal paste."),
                impact="Thermal throttling: the machine gets slower the longer it is used.",
                evidence=temp_evidence,
                confidence=Confidence.MEASURED,
                recommendations=[
                    "Clean the fan and heatsink with compressed air (blow outwards through the exhaust vent).",
                    "Use the laptop on a hard, flat surface so the intake vents are not blocked.",
                    "If temperatures stay high after cleaning, the thermal paste needs replacing.",
                ],
                manual=True,
                data={"temp_c": hottest[1]},
            ))
    elif not ex.have_tool("sensors"):
        findings.append(Finding(
            id="cpu.sensors_missing",
            title="Temperature sensors cannot be read (lm-sensors not installed)",
            category=Category.THERMAL, severity=Severity.LOW,
            summary=("No thermal data is available, so overheating cannot be ruled out as a "
                     "cause of slowdowns."),
            root_cause="The lm-sensors package (providing the 'sensors' command) is not installed.",
            impact="Overheating would go undetected.",
            evidence=[Evidence(source="PATH lookup", detail="sensors: not found",
                               command="command -v sensors")],
            confidence=Confidence.MEASURED, needs_network=True,
            recommendations=["Install it with: sudo apt install lm-sensors && sudo sensors-detect"],
            manual=True,
        ))

    # ------------------------------------------------------ throttling
    cur, mx, mn = cpu_frequencies()
    facts["freq_khz"] = cur[:8]
    facts["freq_max_khz"] = mx
    if cur and mx:
        avg = sum(cur) / len(cur)
        facts["freq_avg_khz"] = avg
        ratio = avg / mx
        facts["freq_ratio"] = round(ratio, 2)
        busy = (load1 / max(1, threads)) >= 0.5
        if ratio < 0.55 and busy:
            findings.append(Finding(
                id="cpu.throttling",
                title=f"CPU is running at {avg / 1e6:.2f} GHz of {mx / 1e6:.2f} GHz while busy",
                category=Category.CPU,
                severity=Severity.HIGH,
                summary=(f"With work queued, the processor should be near its maximum "
                         f"frequency ({mx / 1e6:.2f} GHz), but it is averaging "
                         f"{avg / 1e6:.2f} GHz ({ratio * 100:.0f}%)."),
                root_cause=("The kernel or firmware is holding the clock down - usually because "
                            "of temperature limits, a power profile, or a failing power "
                            "management driver."),
                impact="The machine is artificially slow even when it is doing work.",
                evidence=[
                    Evidence(source="/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq",
                             detail=f"average {avg / 1e6:.2f} GHz, maximum {mx / 1e6:.2f} GHz "
                                    f"({ratio * 100:.0f}%), governor {f.cpu_governor}",
                             command="cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq"),
                    Evidence(source="/proc/loadavg", detail=f"load {load1:.2f} on {threads} threads",
                             command="cat /proc/loadavg")],
                confidence=Confidence.INFERRED,
                recommendations=[
                    "Check temperatures above - heat is the most common cause.",
                    "Check whether a power-saving mode is active (see the governor finding).",
                    "Ensure the laptop is plugged in; some firmware caps frequency on battery.",
                ],
                manual=True,
                data={"ratio": round(ratio, 2)},
            ))

    # ------------------------------------------------------ microcode
    if f.cpu_vendor == "AuthenticAMD":
        logs = ctx.shared_get("log.lines")
        if logs is None:
            from .common import kernel_messages
            logs = kernel_messages(300)
            ctx.share("log.lines", logs)
        uc = match_lines(logs, [r"microcode:.*updated", r"microcode: CPU\d+:"], limit=2)
        if not uc:
            findings.append(Finding(
                id="cpu.microcode_unknown",
                title="Could not confirm that CPU microcode updates are applied",
                category=Category.CPU, severity=Severity.INFO,
                summary=("The kernel log contains no microcode update message. AMD processors "
                         "receive stability and security fixes through microcode loaded at boot."),
                root_cause="Either the amd64-microcode package is missing, or the log was already rotated.",
                evidence=[Evidence(source="/proc/cpuinfo",
                                   detail=f"microcode: {f.cpu_microcode or 'not reported'}",
                                   command="grep microcode /proc/cpuinfo"),
                          Evidence(source="kernel log", detail="no microcode update line found",
                                   command="journalctl -k -b | grep -i microcode")],
                confidence=Confidence.SUSPECTED, needs_network=True,
                recommendations=["Ensure the package is installed: sudo apt install amd64-microcode"],
                manual=True,
            ))

    if not findings:
        summary_bits = [f"load {load1:.2f} on {cores} core(s)"]
        if iowait is not None:
            summary_bits.append(f"iowait {iowait}%")
        if hottest:
            summary_bits.append(f"{hottest[0]} {hottest[1]:.0f} °C")
        findings.append(Finding(
            id="cpu.ok",
            title="Processor load and temperature are normal",
            category=Category.CPU, severity=Severity.OK,
            summary="; ".join(summary_bits) + ".",
            evidence=[Evidence(source="/proc/loadavg", detail=f"load1={load1}",
                               command="cat /proc/loadavg")],
            confidence=Confidence.MEASURED))

    return result("cpu_thermal", "Processor, load and temperature", Category.CPU,
                  findings, facts=facts)
