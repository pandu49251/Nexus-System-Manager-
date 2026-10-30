"""
nexus_doctor.checks.services_startup
====================================

Background services, startup applications and boot performance.

This is where most "my laptop used to be fast" cases are actually solved.  The
single most common cause of a mechanical-disk laptop feeling permanently
sluggish is a **desktop search indexer**: tracker-miner-fs (Mint/Ubuntu) walks
every file, computes metadata and writes it to a database, generating
continuous random I/O that competes with everything else the user does.

Everything here is detected from the live process table plus systemd, so it
reflects what is *actually running now* rather than what is merely enabled.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from ..core import executil as ex
from ..core import privileges
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import find_procs, human_bytes, processes, result, uptime_text

# Processes that are harmless on an SSD but punishing on a mechanical disk.
HEAVY_PROCESSES = {
    "tracker-miner-fs": ("GNOME/GTK file indexer",
                         "Continuously scans the home directory and builds a search database."),
    "tracker-extract": ("file metadata extractor",
                        "Extracts metadata (artist, duration, EXIF) from every file it finds."),
    "baloo_file": ("KDE file indexer", "Indexes files for KDE search."),
    "akonadi": ("KDE PIM storage service", "Runs a database server for mail/calendar data."),
    "zeitgeist": ("activity logger", "Records every file you open into a database."),
    "snapd": ("Snap daemon", "Polls the Snap store and mounts squashfs images (slow on HDD)."),
    "whoopsie": ("error reporting daemon", "Uploads crash reports; spikes CPU after a crash."),
    "apport": ("crash handler", "Collects crash dumps; can spin after repeated failures."),
    "unattended-upgr": ("automatic updates", "Downloads and installs packages in the background."),
    "apt.systemd.daily": ("apt daily job", "Refreshes package lists, generating disk and network load."),
    "packagekitd": ("PackageKit daemon", "Checks for updates periodically."),
    "fwupd": ("firmware updater", "Queries firmware catalogues."),
}

SYSTEMD = ex.isfile("/proc/1/comm") and (ex.read_text("/proc/1/comm") or "").strip() == "systemd"


def systemd_failed() -> List[str]:
    if not SYSTEMD:
        return []
    r = ex.run(["systemctl", "--failed", "--no-pager", "--no-legend", "--plain"], timeout=15)
    out: List[str] = []
    for line in r.lines:
        line = line.strip()
        if not line or line.startswith("0 loaded units"):
            continue
        if line.startswith(("LOAD", "UNIT", "ACTIVE", "SUB", "0 loaded")):
            continue
        # Only real unit lines: name.service / name.target / name.socket ...
        if not re.search(r"[\w@.\-]+\.(service|target|socket|timer|mount|device|path|slice)", line):
            continue
        out.append(re.sub(r"^\u25cf\s*", "", line))
    return out


def systemd_blame() -> List[str]:
    if not SYSTEMD or not ex.have_tool("systemd-analyze"):
        return []
    r = ex.run(["systemd-analyze", "blame", "--no-pager"], timeout=20)
    return [l.strip() for l in r.lines[:12] if l.strip()]


def boot_time() -> Dict[str, float]:
    if not SYSTEMD or not ex.have_tool("systemd-analyze"):
        return {}
    r = ex.run(["systemd-analyze", "--no-pager"], timeout=15)
    if not r.ok:
        return {}
    out: Dict[str, float] = {}
    m = re.search(r"Startup finished in (.+?)\n", r.out + "\n")
    blob = r.out
    for label in ("firmware", "loader", "kernel", "userspace", "initrd"):
        m = re.search(r"([\d.]+)(ms|s|min)\s*\(?" + label, blob)
        if m:
            val = float(m.group(1))
            unit = m.group(2)
            out[label] = val * 60 if unit == "min" else (val if unit == "s" else val / 1000.0)
    m = re.search(r"=\s*([\d.]+)s", blob)
    if m:
        out["total"] = float(m.group(1))
    return out


def autostart_entries() -> List[Dict[str, object]]:
    """XDG autostart .desktop files that will actually run at login."""
    home = privileges.user_home()
    dirs = [os.path.join(home, ".config/autostart"), "/etc/xdg/autostart"]
    out: List[Dict[str, object]] = []
    seen: set = set()
    for d in dirs:
        for fn in ex.listdir(d):
            if not fn.endswith(".desktop"):
                continue
            if fn in seen:
                continue
            seen.add(fn)
            path = os.path.join(d, fn)
            text = ex.read_text(path) or ""
            kv: Dict[str, str] = {}
            in_entry = False
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("["):
                    in_entry = line.lower() == "[desktop entry]"
                    continue
                if in_entry and "=" in line:
                    k, _, v = line.partition("=")
                    kv[k.strip()] = v.strip()
            hidden = kv.get("Hidden", "").lower() == "true"
            override = kv.get("X-XFCE-Autostart-Override", "").lower() == "true"
            nodisplay = kv.get("NoDisplay", "").lower() == "true"
            out.append({"file": path, "name": kv.get("Name", fn[:-8]),
                        "exec": kv.get("Exec", ""),
                        "enabled": not hidden and not override,
                        "only_show_in": kv.get("OnlyShowIn", ""),
                        "system": d.startswith("/etc"),
                        "nodisplay": nodisplay})
    return out


def _has_bluetooth() -> bool:
    if ex.isdir("/sys/class/bluetooth"):
        return True
    return "btusb" in ctx_modules()


def _has_wwan() -> bool:
    for net in ex.listdir("/sys/class/net"):
        if net.startswith(("wwan", "wwp", "usb0")):
            return True
    mods = ctx_modules()
    return bool({"cdc_mbim", "qmi_wwan", "option", "sierra"} & mods)


def _has_printer() -> bool:
    return bool(ex.listdir("/dev/usb")) and any(
        "lp" in n for n in ex.listdir("/dev")) or ex.exists("/dev/lp0")


def ctx_modules() -> set:
    return set(line.split()[0] for line in ex.read_lines("/proc/modules", []))


APT_TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer")


def apt_timers_enabled() -> List[str]:
    """Which of apt's automatic background timers are switched on."""
    if not SYSTEMD:
        return []
    enabled: List[str] = []
    listed = ex.run(["systemctl", "list-unit-files", "--type=timer"], timeout=15)
    if listed.ok:
        for line in listed.lines:
            bits = line.split()
            if len(bits) >= 2 and bits[0] in APT_TIMERS and bits[1] == "enabled":
                enabled.append(bits[0])
        return enabled
    for unit in APT_TIMERS:                      # older systemd, or no list
        r = ex.run(["systemctl", "is-enabled", unit], timeout=10)
        if r.ok and r.first.strip() in ("enabled", "enabled-runtime", "indirect"):
            enabled.append(unit)
    return enabled


@register("services_startup", "Services, startup apps and boot", Category.SERVICES,
          priority=50, description="Running services, indexers, autostart, boot time")
def check_services_startup(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}
    procs = processes()
    facts["process_count"] = len(procs)
    facts["systemd"] = SYSTEMD

    # ------------------------------------------------- heavy background jobs
    heavy_hits: List[Dict[str, object]] = []
    for proc in procs:
        base = os.path.basename((proc.cmdline or proc.comm).split()[0]) if (proc.cmdline or proc.comm) else ""
        for key, (human, what) in HEAVY_PROCESSES.items():
            if base.startswith(key) or key in proc.cmdline:
                heavy_hits.append({"name": base, "pid": proc.pid, "what": what,
                                   "human": human, "rss_mb": proc.rss_mb,
                                   "cmdline": proc.cmdline[:120]})
                break
    facts["heavy_processes"] = heavy_hits

    rotational = f.is_hdd(f.root_device())
    indexers = [h for h in heavy_hits if "tracker" in str(h["name"]) or "baloo" in str(h["name"])]
    if indexers and rotational:
        findings.append(Finding(
            id="services.indexer_running",
            title=f"Desktop search indexer is running on a mechanical disk ({', '.join(str(h['name']) for h in indexers)})",
            category=Category.SERVICES, severity=Severity.HIGH,
            summary=("A file indexer is actively walking the disk. On a 1 TB mechanical "
                     "drive this generates a constant stream of small random reads that "
                     "compete with everything else - it is the classic reason an otherwise "
                     "healthy laptop feels permanently sluggish."),
            root_cause=("tracker-miner-fs (Mint/Ubuntu) starts automatically per user and "
                        "re-indexes on every change. Random I/O on a 5400 rpm disk is ~100 "
                        "operations per second, so the queue never drains."),
            impact=("High iowait, slow application launches, the disk LED flickering "
                    "constantly, and fans spinning up while 'nothing is running'."),
            evidence=[Evidence(source="/proc/<pid>/cmdline",
                               detail="; ".join(f"{h['name']} (pid {h['pid']}, {h['rss_mb']} MB) - {h['what']}"
                                                for h in indexers),
                               raw="\n".join(f"{h['pid']}: {h['cmdline']}" for h in indexers),
                               command="ps aux | grep -E 'tracker|baloo'")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "Disable the indexer. Nothing on an Xfce desktop depends on it (Thunar's "
                "search works without it), and it can be re-enabled at any time.",
                "If you want it, at least let it finish once: the first full index is the "
                "expensive part.",
            ],
            repair_ids=["services.disable_indexers"],
            data={"processes": [h["name"] for h in indexers]},
        ))
    elif heavy_hits:
        findings.append(Finding(
            id="services.heavy_background",
            title=f"{len(heavy_hits)} background service(s) are generating ongoing work",
            category=Category.SERVICES, severity=Severity.LOW,
            summary="; ".join(f"{h['name']} ({h['human']})" for h in heavy_hits[:5]),
            root_cause="Background maintenance services running during interactive use.",
            impact="Periodic slowdowns and disk activity.",
            evidence=[Evidence(source="/proc/<pid>/cmdline",
                               detail="; ".join(f"{h['name']} (pid {h['pid']}) - {h['what']}"
                                                for h in heavy_hits),
                               command="ps aux --sort=-%cpu | head -20")],
            confidence=Confidence.MEASURED,
            recommendations=["Review whether each one is needed; several can be disabled safely."],
            repair_ids=["services.disable_apt_timers"],
            data={"processes": [h["name"] for h in heavy_hits]},
        ))

    # ----------------------------------------------- apt's background timers
    timers = apt_timers_enabled()
    facts["apt_timers"] = timers
    if timers and rotational:
        findings.append(Finding(
            id="services.apt_timers",
            title=f"Automatic package timers ({', '.join(timers)}) refresh in the background",
            category=Category.SERVICES, severity=Severity.MEDIUM,
            summary=("These timers refresh the package list and install updates at times "
                     "you do not choose. On a mechanical disk the refresh produces a burst "
                     "of random reads and writes that can make the whole machine feel "
                     "frozen for several minutes - and it usually happens shortly after "
                     "boot, or in the middle of work."),
            root_cause=("systemd timers apt-daily.timer and apt-daily-upgrade.timer are "
                        "enabled by default on Debian-based distributions, including "
                        "Linux Mint, which already ships its own update manager."),
            impact=("Sudden, unexplained slowdowns with heavy disk activity, often at the "
                    "same time each day; slow boot on the first login after boot."),
            evidence=[Evidence(source="systemctl list-unit-files --type=timer",
                               detail="enabled: " + ", ".join(timers),
                               raw="\n".join(timers),
                               command="systemctl list-unit-files --type=timer | grep apt",
                               ),
                      Evidence(source="sysfs rotational",
                               detail=f"{f.root_device()} is a mechanical disk, so "
                                      f"background writes are felt immediately",
                               command="cat /sys/block/<disk>/queue/rotational")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "Leave updates to Linux Mint's own Update Manager, which shows them and "
                "lets you install when convenient.",
                "If you prefer keeping the timers, schedule them for a time the laptop is "
                "on but idle rather than disabling them.",
            ],
            repair_ids=["services.disable_apt_timers"],
            data={"timers": timers},
        ))
    elif timers:
        findings.append(Finding(
            id="services.apt_timers_ssd",
            title=f"Automatic package timers are enabled ({', '.join(timers)})",
            category=Category.SERVICES, severity=Severity.LOW,
            summary=("apt refreshes its package list automatically. On this disk that is "
                     "rarely noticeable, so this is informational."),
            root_cause="Default Debian/Ubuntu/Mint configuration.",
            impact="Brief periodic disk activity; harmless on a solid-state disk.",
            evidence=[Evidence(source="systemctl list-unit-files --type=timer",
                               detail="enabled: " + ", ".join(timers),
                               command="systemctl list-unit-files --type=timer | grep apt")],
            confidence=Confidence.MEASURED,
            recommendations=["No action needed; turn them off only if you notice stalls."],
            repair_ids=["services.disable_apt_timers"],
            data={"timers": timers},
        ))

    # ------------------------------------------------------ failed units
    if SYSTEMD:
        failed = systemd_failed()
        facts["failed_units"] = failed
        if failed:
            findings.append(Finding(
                id="services.failed_units",
                title=f"{len(failed)} systemd unit(s) failed to start",
                category=Category.SERVICES, severity=Severity.MEDIUM,
                summary=("Failed units often retry in a loop, consuming CPU and filling the "
                         "log. They also mean a feature you expect is not working."),
                root_cause="A service's dependencies or configuration are broken.",
                impact="Log noise, wasted resources, missing functionality.",
                evidence=[Evidence(source="systemctl --failed",
                                   detail="; ".join(l.split()[0] for l in failed[:8]),
                                   raw="\n".join(failed),
                                   command="systemctl --failed")],
                confidence=Confidence.DIRECT,
                recommendations=[
                    "Inspect one with: systemctl status <unit>",
                    "If you do not need it, mask it: sudo systemctl mask <unit>",
                ],
                manual=True,
                data={"units": [l.split()[0] for l in failed]},
            ))

        # ----------------------------------------------------- boot time
        bt = boot_time()
        facts["boot_time"] = bt
        if bt:
            users = bt.get("userspace", 0)
            total = bt.get("total", 0)
            if users >= 45 or total >= 90:
                blame = systemd_blame()
                findings.append(Finding(
                    id="services.slow_boot",
                    title=f"Boot takes {total:.0f} s ({users:.0f} s of it starting services)",
                    category=Category.BOOT, severity=Severity.MEDIUM,
                    summary=(f"systemd-analyze reports a {total:.0f} second start-up, of which "
                             f"{users:.0f} s is userspace service start-up."),
                    root_cause=("On a mechanical disk, services that start in parallel all "
                                "seek at once and serialise behind each other."),
                    impact="Long wait before the desktop is usable.",
                    evidence=[Evidence(source="systemd-analyze",
                                       detail="; ".join(f"{k}={v:.1f}s" for k, v in bt.items()),
                                       raw="\n".join(systemd_blame()),
                                       command="systemd-analyze && systemd-analyze blame | head"),
                              Evidence(source="systemd-analyze blame",
                                       detail="; ".join(blame[:6]) or "n/a",
                                       command="systemd-analyze blame | head -12")],
                    confidence=Confidence.DIRECT,
                    recommendations=[
                        "Review the slowest units listed above and disable the ones you do not need.",
                        "An SSD reduces this dramatically; no software tuning matches it.",
                    ],
                    manual=True,
                    data={"boot_seconds": total},
                ))

    # ------------------------------------------------------- autostart
    entries = autostart_entries()
    enabled = [e for e in entries if e["enabled"]]
    facts["autostart"] = {"total": len(entries), "enabled": len(enabled),
                          "names": [e["name"] for e in enabled]}
    if len(enabled) >= 8:
        findings.append(Finding(
            id="services.many_autostart",
            title=f"{len(enabled)} applications start automatically at login",
            category=Category.BOOT, severity=Severity.MEDIUM,
            summary=("Every autostart application reads libraries and data from disk at "
                     "login. On a mechanical disk they queue behind each other, so the "
                     "desktop stays busy for a long time after it appears."),
            root_cause="Applications registered themselves in ~/.config/autostart or /etc/xdg/autostart.",
            impact="Slow login and a sluggish first minute or two of every session.",
            evidence=[Evidence(source="~/.config/autostart and /etc/xdg/autostart",
                               detail=", ".join(str(e["name"]) for e in enabled[:12]),
                               raw="\n".join(f"{'enabled ' if e['enabled'] else 'disabled'} "
                                             f"{e['file']}" for e in entries),
                               command="ls ~/.config/autostart /etc/xdg/autostart")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "Disable the ones you do not need in Settings > Session and Startup > "
                "Application Autostart.",
                "Disabling only removes it from start-up - the program stays installed.",
            ],
            repair_ids=["services.trim_autostart"],
            data={"count": len(enabled)},
        ))

    # ------------------------------------- services for absent hardware
    if SYSTEMD:
        unused: List[str] = []
        mm_running = any("ModemManager" in p.cmdline for p in procs)
        bt_running = any(p.name.startswith(("bluetoothd",)) for p in procs)
        cups_running = any(p.name.startswith(("cupsd",)) for p in procs)
        if mm_running and not _has_wwan():
            unused.append("ModemManager (no mobile broadband hardware detected)")
        if bt_running and not _has_bluetooth():
            unused.append("bluetooth (no Bluetooth adapter detected)")
        if unused:
            findings.append(Finding(
                id="services.unused_hw_services",
                title=f"Services are running for hardware this machine does not have ({len(unused)})",
                category=Category.SERVICES, severity=Severity.LOW,
                summary="; ".join(unused),
                root_cause="Default services start regardless of whether their hardware exists.",
                impact="Small but constant memory and CPU/disk overhead.",
                evidence=[Evidence(source="/proc/<pid>/cmdline and /sys/class",
                                   detail="; ".join(unused),
                                   command="ps aux | grep -E 'ModemManager|bluetoothd'")],
                confidence=Confidence.INFERRED,
                recommendations=["They can be disabled safely and re-enabled in one command if needed."],
                repair_ids=["services.disable_unused"],
                data={"services": unused},
            ))

    if not findings:
        findings.append(Finding(
            id="services.ok",
            title="Background services look reasonable",
            category=Category.SERVICES, severity=Severity.OK,
            summary=(f"{len(procs)} processes running, no file indexer active, no failed "
                     f"systemd units (uptime {uptime_text(f.uptime_s)})."),
            evidence=[Evidence(source="/proc", detail=f"{len(procs)} processes",
                               command="ps -e --no-headers | wc -l")],
            confidence=Confidence.MEASURED))

    return result("services_startup", "Services, startup apps and boot", Category.SERVICES,
                  findings, facts=facts)
