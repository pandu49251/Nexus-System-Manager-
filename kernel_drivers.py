"""
nexus_doctor.checks.kernel_drivers
==================================

Kernel state, loadable modules and firmware.

Two things are checked that people rarely think of but that cause a lot of
"my laptop is unreliable" reports:

* **Kernel taint** - if a proprietary or out-of-tree module has been loaded,
  the kernel flags itself as unsupported.  Such modules are a very common
  source of freezes and suspend failures, and they are the reason kernel
  developers will ignore a bug report.
* **Failed module builds (DKMS)** - a driver that failed to compile means
  hardware that silently does not work (usually Wi-Fi or graphics).
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Tuple

from ..core import executil as ex
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import human_bytes, match_lines, result

TAINT_BITS = [
    (1, "P", "a proprietary (non-GPL) module has been loaded"),
    (2, "F", "a module was force-loaded"),
    (512, "W", "the kernel has issued a warning (WARN_ON)"),
    (1024, "C", "a staging (experimental-quality) driver is in use"),
    (4096, "O", "an out-of-tree module is loaded"),
    (8192, "E", "an unsigned module was loaded while Secure Boot is enabled"),
    (16384, "L", "a soft lockup occurred"),
    (32768, "K", "a live-patched kernel is running"),
]

# Modules that matter for this class of laptop and what their absence means.
EXPECTED_MODULES = {
    "ideapad_laptop": ("IdeaPad ACPI platform driver",
                       "Provides battery-conservation mode, hotkeys and rfkill switching "
                       "for IdeaPad models."),
    "sp5100_tco": ("AMD watchdog timer", "Hardware watchdog for AMD chipsets."),
    "k10temp": ("AMD temperature sensor", "Exposes CPU temperature to lm-sensors."),
    "amdgpu": ("AMD graphics driver", "Modern AMD GPU driver."),
    "zram": ("compressed RAM block device", "Needed for zram swap."),
}


def taint_flags(value: int) -> List[Tuple[str, str]]:
    return [(flag, text) for bit, flag, text in TAINT_BITS if value & bit]


def secure_boot_enabled() -> Optional[bool]:
    """Read the UEFI Secure Boot state from the efivar (Linux 6.6+ also has a sysfs file)."""
    path = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    if ex.isfile(path):
        data = ex.read_bytes(path, 5)
        if data and len(data) >= 5:
            return data[4] == 1
    val = ex.read_text("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    return None


def boot_images() -> List[str]:
    names = []
    for fn in ex.listdir("/boot"):
        if fn.startswith(("vmlinuz", "vmlinux", "kernel")):
            names.append(fn)
    return names


@register("kernel_drivers", "Kernel, modules and drivers", Category.KERNEL, priority=45,
          description="Kernel taint, modules, DKMS, firmware, Secure Boot")
def check_kernel_drivers(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}
    facts["kernel"] = f.kernel
    facts["cmdline"] = f.cmdline

    # --------------------------------------------------------- kernel taint
    raw = (ex.read_text("/proc/sys/kernel/tainted") or "0").strip()
    try:
        taint = int(raw)
    except ValueError:
        taint = 0
    facts["tainted"] = taint
    flags = taint_flags(taint)
    if flags:
        worst = any(flag in ("P", "O", "E") for flag, _t in flags)
        findings.append(Finding(
            id="kernel.tainted",
            title=f"The kernel is flagged as tainted ({', '.join(flag for flag, _t in flags)})",
            category=Category.KERNEL,
            severity=Severity.MEDIUM if worst else Severity.LOW,
            summary="; ".join(text for _flag, text in flags) + ".",
            root_cause=("A module outside the mainline kernel is loaded, or the kernel has "
                        "hit a warning. Proprietary and out-of-tree drivers (commonly "
                        "VirtualBox, NVIDIA, or vendor Wi-Fi drivers) are the usual cause."),
            impact=("Reduced stability - these modules are a frequent cause of freezes and "
                    "suspend/resume failures - and upstream bug reports will be rejected."),
            evidence=[Evidence(source="/proc/sys/kernel/tainted",
                               detail=f"value {taint} = " + ", ".join(
                                   f"{flag} ({text})" for flag, text in
                                   [(fl, tx) for fl, tx in [(f2, t2) for _b, f2, t2 in TAINT_BITS
                                                            if taint & _b]]),
                               command="cat /proc/sys/kernel/tainted"),
                      Evidence(source="/proc/modules",
                               detail="loaded out-of-tree modules: " + ", ".join(
                                   l.split()[0] for l in ex.read_lines("/proc/modules", [])
                                   if "(O)" in l or "(PO)" in l) or "none marked",
                               command="grep -E '\\((O|PO)\\)' /proc/modules")],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Identify the culprit: grep -E '\\((O|PO|E)\\)' /proc/modules",
                "Remove or replace that driver if stability matters more than the feature.",
            ],
            manual=True,
            data={"taint": taint},
        ))

    # ------------------------------------------------------------- cmdline
    notable_args = [a for a in f.cmdline_args
                    if a in ("nomodeset", "acpi=off", "acpi_osi=", "pci=nomsi",
                             "mitigations=off", "maxcpus=1", "nosmp")]
    risky = [a for a in f.cmdline_args if a.startswith(("nomodeset", "maxcpus=1", "nosmp"))]
    facts["notable_cmdline"] = notable_args
    if risky:
        findings.append(Finding(
            id="kernel.risky_cmdline",
            title=f"Kernel command line contains performance-limiting options: {', '.join(risky)}",
            category=Category.KERNEL, severity=Severity.HIGH,
            summary="These parameters disable hardware features and will make the machine much slower.",
            root_cause="Usually added to work around a boot problem and never removed.",
            evidence=[Evidence(source="/proc/cmdline", detail=f.cmdline,
                               command="cat /proc/cmdline")],
            confidence=Confidence.DIRECT, manual=True, reboot_required=True,
            recommendations=["Edit /etc/default/grub, remove them, run 'sudo update-grub', and reboot."]))

    # ---------------------------------------------------------------- DKMS
    if ex.have_tool("dkms"):
        r = ex.run(["dkms", "status"], timeout=30, root=True)
        if r.ok and r.out.strip():
            facts["dkms"] = r.lines
            bad = [l for l in r.lines if re.search(r"error|failed|added|built", l, re.I)
                   and not re.search(r"installed", l, re.I)]
            if bad:
                findings.append(Finding(
                    id="kernel.dkms_failed",
                    title=f"{len(bad)} DKMS module(s) are not properly installed",
                    category=Category.KERNEL, severity=Severity.HIGH,
                    summary=("Dynamic kernel modules failed to build or install for the "
                             "running kernel, so the hardware they drive does not work."),
                    root_cause="Kernel headers are missing, or the module source does not compile against this kernel.",
                    impact="Wi-Fi, graphics or other hardware silently unavailable.",
                    evidence=[Evidence(source="dkms status", detail="; ".join(l[:90] for l in bad[:5]),
                                       raw="\n".join(r.lines), command="sudo dkms status",
                                       root_required=True)],
                    confidence=Confidence.DIRECT, needs_root=True,
                    recommendations=[
                        f"Install headers: sudo apt install linux-headers-{f.kernel}",
                        "Then rebuild: sudo dkms autoinstall",
                    ],
                    manual=True,
                ))

    # ------------------------------------------------------------ firmware
    logs = ctx.shared_get("log.lines") or []
    fw = [(p, l) for p, l in match_lines(logs, [r"failed to load firmware",
                                                r"Direct firmware load for .* failed"], limit=8)
          if not re.search(r"amdgpu|radeon", l, re.I)]
    if fw:
        files = sorted({re.search(r"for (\S+) failed", line).group(1) if re.search(
            r"for (\S+) failed", line) else line[:40] for _p, line in fw})
        findings.append(Finding(
            id="kernel.firmware_missing",
            title=f"{len(files)} firmware file(s) could not be loaded",
            category=Category.KERNEL, severity=Severity.MEDIUM,
            summary="Hardware asked for firmware that is not present on the system.",
            root_cause="The linux-firmware package is missing or older than the kernel.",
            impact="Affected hardware (often Wi-Fi or Bluetooth) does not work.",
            evidence=[Evidence(source="kernel log",
                               detail=", ".join(files[:6]),
                               raw="\n".join(line[:160] for _p, line in fw),
                               command="dmesg | grep -i firmware")],
            confidence=Confidence.DIRECT, needs_network=True,
            recommendations=["Install or update: sudo apt install --reinstall linux-firmware"],
            manual=True,
            data={"files": files},
        ))

    # -------------------------------------------------------- Secure Boot
    sb = secure_boot_enabled()
    facts["secure_boot"] = sb
    if sb and (taint & 8192 or taint & 4096):
        findings.append(Finding(
            id="kernel.secureboot_unsigned",
            title="Secure Boot is on and unsigned modules are loaded",
            category=Category.KERNEL, severity=Severity.LOW,
            summary="Unsigned modules cannot normally load under Secure Boot; the system is "
                    "in a mixed state that can break after a firmware update.",
            evidence=[Evidence(source="UEFI efivar", detail="SecureBoot = enabled",
                               command="mokutil --sb-state")],
            confidence=Confidence.DIRECT, manual=True,
            recommendations=["Sign the modules (MOK) or disable Secure Boot in firmware setup."]))

    # ------------------------------------------------ IdeaPad platform dirv
    vendor = f.machine.vendor.lower()
    if "lenovo" in vendor or "ideapad" in f.machine.product.lower():
        loaded = f.has_module("ideapad_laptop")
        facts["ideapad_laptop"] = loaded
        if not loaded:
            findings.append(Finding(
                id="kernel.ideapad_module_missing",
                title="The IdeaPad ACPI platform driver (ideapad_laptop) is not loaded",
                category=Category.KERNEL, severity=Severity.LOW,
                summary=("This is a Lenovo IdeaPad, but the platform driver that provides "
                         "hotkeys, the Wi-Fi/Bluetooth rfkill switch and battery charge "
                         "thresholds is not active."),
                root_cause="The module is not loaded on this kernel (sometimes blacklisted, "
                           "sometimes unavailable).",
                impact="Function keys, airplane mode and battery-conservation mode may not work.",
                evidence=[Evidence(source="/proc/modules", detail="ideapad_laptop: not present",
                                   command="lsmod | grep ideapad"),
                          Evidence(source="/sys/devices/virtual/dmi/id/product_name",
                                   detail=f"{f.machine.vendor} {f.machine.product}",
                                   command="cat /sys/devices/virtual/dmi/id/product_name")],
                confidence=Confidence.DIRECT,
                recommendations=["Try loading it: sudo modprobe ideapad_laptop",
                                 "If it works, it will be loaded automatically next boot."],
                manual=True))

    # ------------------------------------------------------ /boot contents
    images = boot_images()
    facts["boot_images"] = images
    if len(images) > 3:
        findings.append(Finding(
            id="kernel.many_kernels",
            title=f"{len(images)} kernel images are installed in /boot",
            category=Category.KERNEL, severity=Severity.LOW,
            summary="Old kernels accumulate and consume disk space on every update.",
            root_cause="Automatic updates keep previous kernels as a fallback.",
            impact="Wasted space; on a small /boot partition, updates can fail outright.",
            evidence=[Evidence(source="/boot", detail=", ".join(images[:8]),
                               command="ls /boot")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "Remove old ones from Update Manager > View > Linux Kernels (keep the "
                "current one plus one fallback).",
                "Never remove the running kernel: " + f.kernel,
            ],
            manual=True,
            data={"images": images},
        ))

    if not findings:
        findings.append(Finding(
            id="kernel.ok",
            title=f"Kernel {f.kernel} is running cleanly",
            category=Category.KERNEL, severity=Severity.OK,
            summary="No taint, no failed module builds and no missing firmware were detected.",
            evidence=[Evidence(source="/proc/sys/kernel/tainted", detail=f"tainted = {taint}",
                               command="cat /proc/sys/kernel/tainted"),
                      Evidence(source="/proc/cmdline", detail=f.cmdline[:160],
                               command="cat /proc/cmdline")],
            confidence=Confidence.DIRECT))

    return result("kernel_drivers", "Kernel, modules and drivers", Category.KERNEL,
                  findings, facts=facts)
