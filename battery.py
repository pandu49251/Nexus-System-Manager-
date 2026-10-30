"""
nexus_doctor.checks.battery
===========================

Battery health and power state.

A worn battery causes more than short run-time: as internal resistance rises,
the pack can no longer supply peak current, and some laptops then throttle the
CPU to stay alive - which looks exactly like "the laptop has become slow".

Wear is computed from the values the firmware itself reports::

    wear % = 100 x (1 - energy_full / energy_full_design)

That ratio is the industry-standard definition of battery health, and it is
reported verbatim so the user can verify it with ``upower`` themselves.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..core import executil as ex
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import human_bytes, result

PS_BASE = "/sys/class/power_supply"


def _int(value: Optional[str]) -> Optional[int]:
    try:
        return int((value or "").strip())
    except (ValueError, AttributeError):
        return None


def power_supplies() -> List[Dict[str, object]]:
    """Parse every entry under /sys/class/power_supply."""
    out: List[Dict[str, object]] = []
    for name in ex.listdir(PS_BASE):
        base = f"{PS_BASE}/{name}"
        uevent = ex.read_text(f"{base}/uevent") or ""
        data: Dict[str, str] = {}
        for line in uevent.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                data[k.strip().replace("POWER_SUPPLY_", "")] = v.strip()
        if not data:
            # Fall back to individual sysfs attributes.
            for attr in ("type", "status", "capacity", "capacity_level",
                         "energy_full", "energy_full_design", "energy_now",
                         "charge_full", "charge_full_design", "charge_now",
                         "cycle_count", "voltage_now", "voltage_min_design",
                         "health", "manufacturer", "model_name", "technology",
                         "present", "serial_number"):
                v = ex.read_text(f"{base}/{attr}")
                if v is not None:
                    data[attr.upper()] = v.strip()
        if not data:
            continue
        data["_name"] = name
        out.append(data)  # type: ignore[arg-type]
    return out


def _pick_capacity(ps: Dict[str, object], design_key: str, full_key: str,
                   now_key: str) -> Optional[Dict[str, float]]:
    design = _int(str(ps.get(design_key, ""))) or 0
    full = _int(str(ps.get(full_key, ""))) or 0
    now = _int(str(ps.get(now_key, "")))
    if not design or not full:
        return None
    return {"design": design, "full": full, "now": now,
            "wear_pct": round(100.0 * (1.0 - full / design), 1),
            "charge_pct": round(100.0 * now / full, 1) if now is not None else None,
            "unit": "energy (µWh)" if design_key.startswith("ENERGY") else "charge (µAh)"}


def parse_upower(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    return out


@register("battery", "Battery and power", Category.BATTERY, priority=30,
          description="Battery wear, health, charge state, charger")
def check_battery(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}
    supplies = power_supplies()
    facts["power_supplies"] = [{k: v for k, v in s.items()} for s in supplies]

    batteries = [s for s in supplies if str(s.get("TYPE", "")).lower() == "battery"]
    mains = [s for s in supplies if str(s.get("TYPE", "")).lower() == "mains"]

    if not supplies:
        return result("battery", "Battery and power", Category.BATTERY,
                      [Finding(id="battery.no_ps", title="No power supply information available",
                               category=Category.BATTERY, severity=Severity.INFO,
                               summary="This kernel exposes no /sys/class/power_supply entries "
                                       "(typical inside a virtual machine or container).",
                               evidence=[Evidence(source="/sys/class/power_supply",
                                                  detail="directory missing or empty",
                                                  command="ls /sys/class/power_supply")],
                               confidence=Confidence.DIRECT, manual=True)],
                      state="degraded", notes="no power supply data")

    for m in mains:
        facts["ac_online"] = str(m.get("ONLINE", ""))

    if not batteries:
        if f.is_laptop():
            findings.append(Finding(
                id="battery.missing",
                title="This is a laptop but no battery is detected",
                category=Category.BATTERY, severity=Severity.MEDIUM,
                summary="The firmware reports a portable chassis, yet no battery is present.",
                root_cause="The battery may be removed, disconnected, or faulty; the AC adapter is the only source.",
                impact="Any power cut or unplugged cable shuts the machine down instantly.",
                evidence=[Evidence(source="/sys/class/power_supply",
                                   detail=f"entries: {', '.join(str(s.get('_name')) for s in supplies)} (no battery)",
                                   command="ls /sys/class/power_supply"),
                          Evidence(source="/sys/devices/virtual/dmi/id/chassis_type",
                                   detail=f"chassis type: {f.machine.chassis}",
                                   command="cat /sys/devices/virtual/dmi/id/chassis_type")],
                confidence=Confidence.INFERRED,
                recommendations=["Check in the firmware setup (F2 at boot) whether a battery is reported.",
                                 "Reseat the battery connector if you are comfortable opening the case."],
                manual=True))
        else:
            findings.append(Finding(
                id="battery.none",
                title="No battery present (desktop or virtual machine)",
                category=Category.BATTERY, severity=Severity.INFO,
                summary="No battery was detected; power checks are not applicable.",
                evidence=[Evidence(source="/sys/class/power_supply",
                                   detail=f"entries: {', '.join(str(s.get('_name')) for s in supplies)}",
                                   command="ls /sys/class/power_supply")],
                confidence=Confidence.DIRECT))
        return result("battery", "Battery and power", Category.BATTERY, findings, facts=facts)

    for bat in batteries:
        name = str(bat.get("_name", "BAT0"))
        caps = (_pick_capacity(bat, "ENERGY_FULL_DESIGN", "ENERGY_FULL", "ENERGY_NOW")
                or _pick_capacity(bat, "CHARGE_FULL_DESIGN", "CHARGE_FULL", "CHARGE_NOW"))
        status = str(bat.get("STATUS", "Unknown"))
        health = str(bat.get("HEALTH", ""))
        cycles = _int(str(bat.get("CYCLE_COUNT", "")))
        tech = str(bat.get("TECHNOLOGY", ""))
        model = str(bat.get("MODEL_NAME", "")) or str(bat.get("MANUFACTURER", ""))
        voltage_now = _int(str(bat.get("VOLTAGE_NOW", "")))
        voltage_min = _int(str(bat.get("VOLTAGE_MIN_DESIGN", "")))
        capacity_level = str(bat.get("CAPACITY_LEVEL", ""))

        facts[f"battery.{name}"] = {
            "status": status, "health": health, "cycles": cycles,
            "technology": tech, "model": model,
            "wear_pct": caps["wear_pct"] if caps else None,
            "charge_pct": caps["charge_pct"] if caps else _int(str(bat.get("CAPACITY", ""))),
        }

        base_ev = [Evidence(source=f"{PS_BASE}/{name}/uevent",
                            detail="; ".join(f"{k}={v}" for k, v in sorted(bat.items())
                                             if k in ("STATUS", "HEALTH", "CAPACITY",
                                                      "CAPACITY_LEVEL", "CYCLE_COUNT",
                                                      "ENERGY_FULL", "ENERGY_FULL_DESIGN",
                                                      "CHARGE_FULL", "CHARGE_FULL_DESIGN",
                                                      "TECHNOLOGY", "MODEL_NAME",
                                                      "MANUFACTURER", "VOLTAGE_NOW",
                                                      "VOLTAGE_MIN_DESIGN")),
                            raw="\n".join(f"{k}={v}" for k, v in sorted(bat.items()) if not k.startswith("_")),
                            command=f"cat {PS_BASE}/{name}/uevent")]

        # ---------------------------------------------------------- wear
        if caps:
            wear = caps["wear_pct"]
            facts[f"battery.{name}.wear_pct"] = wear
            if wear >= 60:
                sev, verdict = Severity.HIGH, "badly worn"
            elif wear >= 40:
                sev, verdict = Severity.MEDIUM, "noticeably worn"
            elif wear >= 25:
                sev, verdict = Severity.LOW, "starting to wear"
            else:
                sev, verdict = None, "healthy"
            if sev is not None:
                unit = caps["unit"]
                findings.append(Finding(
                    id=f"battery.wear_{name}",
                    title=f"Battery is {verdict}: {wear:.0f}% of its original capacity is gone",
                    category=Category.BATTERY, severity=sev,
                    summary=(f"The battery now holds {caps['full']:,} {unit} against a design "
                             f"capacity of {caps['design']:,} - about "
                             f"{100 - wear:.0f}% of what it had when new."),
                    root_cause=("Lithium-ion cells lose capacity through charge cycles and age. "
                                "As they wear, internal resistance rises."),
                    impact=("Short run-time, and on many laptops CPU throttling because the "
                            "pack can no longer deliver peak current."),
                    evidence=base_ev,
                    confidence=Confidence.MEASURED,
                    recommendations=[
                        "Replace the battery if you need portable use; run-time will keep falling.",
                        "Until then, keep the laptop plugged in for heavy work.",
                        "Avoid deep discharges - they accelerate wear.",
                    ],
                    manual=True,
                    data={"wear_pct": wear},
                ))
            elif caps:
                findings.append(Finding(
                    id=f"battery.wear_ok_{name}",
                    title=f"Battery health is good ({100 - wear:.0f}% of design capacity)",
                    category=Category.BATTERY, severity=Severity.OK,
                    summary=f"The battery retains {100 - wear:.0f}% of its original capacity.",
                    evidence=base_ev, confidence=Confidence.MEASURED))

        # -------------------------------------------------------- health
        if health and health.lower() not in ("good", "unknown"):
            findings.append(Finding(
                id=f"battery.health_{name}",
                title=f"Battery reports health status: {health}",
                category=Category.BATTERY, severity=Severity.HIGH,
                summary=f"The firmware reports the battery's health as '{health}'.",
                root_cause="Firmware-level fault detection in the battery pack.",
                impact="Possible sudden shutdowns or refusal to charge.",
                evidence=base_ev, confidence=Confidence.DIRECT,
                recommendations=["Back up work frequently; plan to replace the battery."],
                manual=True))

        # ------------------------------------------------------- cycles
        if cycles is not None and cycles >= 500:
            findings.append(Finding(
                id=f"battery.cycles_{name}",
                title=f"Battery has completed {cycles} charge cycles",
                category=Category.BATTERY,
                severity=Severity.MEDIUM if cycles >= 800 else Severity.LOW,
                summary=(f"{cycles} full charge cycles. Most laptop cells are specified for "
                         f"roughly 300-500 cycles before noticeable degradation."),
                root_cause="Cumulative chemical ageing from charge/discharge cycles.",
                evidence=base_ev, confidence=Confidence.DIRECT,
                recommendations=["Expect reduced run-time; consider a replacement."],
                manual=True))

        # ---------------------------------------------------- discharge
        charge_pct = caps["charge_pct"] if caps else _int(str(bat.get("CAPACITY", "")))
        if (status.lower().startswith("discharging") and charge_pct is not None
                and charge_pct <= 15):
            findings.append(Finding(
                id=f"battery.low_{name}",
                title=f"Battery is at {charge_pct}% and discharging",
                category=Category.BATTERY, severity=Severity.MEDIUM,
                summary="The machine will shut down soon unless it is plugged in.",
                root_cause="Low state of charge while running on battery.",
                impact="Unsaved work will be lost if it reaches zero.",
                evidence=base_ev, confidence=Confidence.MEASURED,
                recommendations=["Plug in the charger or save your work and shut down."],
                manual=True))

        # ------------------------------------------------- weak-cell tell
        if voltage_now and voltage_min and voltage_now < voltage_min * 0.95:
            findings.append(Finding(
                id=f"battery.voltage_sag_{name}",
                title=f"Battery voltage ({voltage_now / 1e6:.2f} V) is below its design minimum",
                category=Category.BATTERY, severity=Severity.MEDIUM,
                summary=(f"Pack voltage has sagged below the design minimum of "
                         f"{voltage_min / 1e6:.2f} V under load."),
                root_cause="High internal resistance from aged or damaged cells.",
                impact="Sudden shutdowns under CPU load, even when the charge indicator is not empty.",
                evidence=base_ev, confidence=Confidence.MEASURED,
                recommendations=["This is a strong indicator that the battery should be replaced."],
                manual=True))

    # ------------------------------------------------------------ TLP
    if f.is_laptop() and not f.has_package("tlp") and not f.has_module("tlp"):
        findings.append(Finding(
            id="battery.no_tlp",
            title="No laptop power-management tool is installed",
            category=Category.POWER, severity=Severity.LOW,
            summary=("TLP is not installed. It applies power-saving settings to the CPU, "
                     "disk and wireless automatically, which usually extends battery life "
                     "and reduces heat on AMD laptops."),
            root_cause="Optional package, not installed by default on Linux Mint.",
            evidence=[Evidence(source="package database", detail="tlp: not installed",
                               command="dpkg -l tlp")],
            confidence=Confidence.MEASURED, needs_network=True,
            recommendations=["Install with: sudo apt install tlp && sudo tlp start"],
            manual=True))

    return result("battery", "Battery and power", Category.BATTERY, findings, facts=facts)
