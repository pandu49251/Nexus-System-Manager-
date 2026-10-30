"""
nexus_doctor.checks.graphics
============================

Graphics driver, rendering path and desktop compositing.

On integrated AMD Radeon graphics there are three ways to end up with a
terrible desktop experience, and they need different fixes:

1. **Software rendering** (``llvmpipe``) - the GPU is not being used at all, so
   the CPU draws every frame.  Causes: ``nomodeset`` in the kernel command
   line, missing firmware, or a driver that failed to load.
2. **No hardware acceleration for the compositor** - Xfce's window compositor
   needs GPU work; on a weak integrated GPU with a mechanical disk it can make
   window dragging and video stutter badly.
3. **Driver mismatch** - AMD "Stoney Ridge" GPUs are supported by both the
   ``radeon`` and ``amdgpu`` drivers; which one is active determines
   performance, tear-free behaviour and suspend reliability.

All three are distinguished here with evidence rather than guesswork.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from ..core import executil as ex
from ..core import privileges
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import match_lines, result

PCI_LINE = re.compile(r"^(?P<slot>[\w:.]+)\s+(?P<cls>[^:]+):\s+(?P<desc>.*)$")
DRIVER_RE = re.compile(r"Kernel driver in use:\s*(\S+)")
MODULES_RE = re.compile(r"Kernel modules:\s*(.+)")


def pci_devices() -> List[Dict[str, str]]:
    """Parse ``lspci -k`` into device records (empty list if lspci is absent)."""
    if not ex.have_tool("lspci"):
        return []
    r = ex.run(["lspci", "-k"], timeout=15)
    if not r.ok:
        return []
    out: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None
    for line in r.lines:
        if not line.strip():
            continue
        if line.startswith((" ", "\t")):
            if current is None:
                continue
            m = DRIVER_RE.search(line)
            if m:
                current["driver"] = m.group(1)
            m = MODULES_RE.search(line)
            if m:
                current["modules"] = m.group(1).strip()
            if line.strip().startswith("Subsystem:"):
                current["subsystem"] = line.split(":", 1)[1].strip()
            continue
        m = PCI_LINE.match(line)
        if m:
            current = {"slot": m.group("slot"), "class": m.group("cls").strip(),
                       "description": m.group("desc").strip(), "driver": "",
                       "modules": "", "subsystem": ""}
            out.append(current)
    return out


def gpus(devices: List[Dict[str, str]]) -> List[Dict[str, str]]:
    interesting = ("VGA compatible controller", "3D controller", "Display controller")
    return [d for d in devices if any(c in d.get("class", "") for c in interesting)]


def drm_info() -> Dict[str, str]:
    """Driver binding information straight from sysfs (works without lspci)."""
    info: Dict[str, str] = {}
    for card in ex.listdir("/sys/class/drm"):
        if not card.startswith("card"):
            continue
        link = ex.readlink(f"/sys/class/drm/{card}/device/driver")
        if link:
            info[card] = os.path.basename(link.rstrip("/"))
    return info


def xorg_log_errors() -> Tuple[str, List[str]]:
    """Return (log path, error lines) from the X server log."""
    candidates = ["/var/log/Xorg.0.log",
                  os.path.join(privileges.user_home(), ".local/share/xorg/Xorg.0.log"),
                  "/var/log/Xorg.1.log"]
    for path in candidates:
        if ex.isfile(path):
            text = ex.read_text(path) or ""
            errs = [l.strip() for l in text.splitlines() if "(EE)" in l]
            return path, errs[:15]
    return "", []


def xfconf_get(channel: str, prop: str) -> Optional[str]:
    if not ex.have_tool("xfconf-query") or not privileges.has_gui_session():
        return None
    r = privileges.run_as_user(["xfconf-query", "-c", channel, "-p", prop], timeout=8)
    if r.ok:
        return r.first.strip()
    return None


def renderer_info() -> Tuple[str, str]:
    """(renderer string, source command) from glxinfo, if available."""
    if not ex.have_tool("glxinfo") or not privileges.has_gui_session():
        return "", ""
    r = privileges.run_as_user(["glxinfo", "-B"], timeout=12)
    if not r.ok:
        return "", "glxinfo -B (failed)"
    for line in r.lines:
        if "OpenGL renderer string" in line:
            return line.split(":", 1)[1].strip(), "glxinfo -B"
    return "", "glxinfo -B"


@register("graphics", "Graphics, drivers and compositing", Category.GRAPHICS, priority=40,
          description="GPU driver, hardware vs software rendering, Xfce compositing")
def check_graphics(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}
    logs = ctx.shared_get("log.lines") or []

    devices = pci_devices()
    cards = gpus(devices)
    facts["pci_gpus"] = cards
    facts["drm"] = drm_info()

    if not devices:
        findings.append(Finding(
            id="graphics.no_lspci",
            title="Graphics hardware could not be enumerated (pciutils not installed)",
            category=Category.GRAPHICS, severity=Severity.INFO,
            summary="The lspci tool is missing, so the graphics controller cannot be identified precisely.",
            root_cause="The pciutils package is not installed.",
            evidence=[Evidence(source="PATH lookup", detail="lspci: not found",
                               command="command -v lspci"),
                      Evidence(source="/sys/class/drm",
                               detail=f"DRM driver bindings: {facts['drm'] or 'none found'}",
                               command="ls -l /sys/class/drm/*/device/driver")],
            confidence=Confidence.DIRECT, needs_network=True,
            recommendations=["Install with: sudo apt install pciutils"],
            manual=True))

    # ------------------------------------------------- nomodeset (severe)
    if "nomodeset" in f.cmdline_args:
        findings.append(Finding(
            id="graphics.nomodeset",
            title="Kernel is running with 'nomodeset' - the GPU is effectively disabled",
            category=Category.GRAPHICS, severity=Severity.CRITICAL,
            summary=("The kernel parameter 'nomodeset' prevents a graphics driver from "
                     "taking over the display. The system falls back to a basic framebuffer "
                     "and all drawing is done by the CPU."),
            root_cause=("It is normally added temporarily to work around a boot problem and "
                        "then forgotten. While it is set, no GPU acceleration is possible."),
            impact=("Very slow and stuttering desktop, no video acceleration, poor screen "
                    "resolution, and heavy CPU use for simple animations."),
            evidence=[Evidence(source="/proc/cmdline", detail=f.cmdline,
                               command="cat /proc/cmdline")],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Edit /etc/default/grub, remove 'nomodeset' from GRUB_CMDLINE_LINUX_DEFAULT, "
                "then run: sudo update-grub",
                "Then reboot and re-run this scan.",
            ],
            manual=True, reboot_required=True))

    # ------------------------------------------------------- GPU + driver
    for card in cards:
        desc = card.get("description", "")
        driver = card.get("driver", "")
        modules = card.get("modules", "")
        facts["gpu"] = desc
        facts["gpu_driver"] = driver
        is_amd = bool(re.search(r"AMD|ATI|Radeon", desc, re.I))
        ev = [Evidence(source=f"lspci -k ({card['slot']})",
                       detail=f"{card['class']}: {desc}" +
                              (f"\nkernel driver in use: {driver}" if driver else
                               "\nkernel driver in use: (none)") +
                              (f"\navailable modules: {modules}" if modules else ""),
                       raw=f"{card['slot']} {card['class']}: {desc}\n"
                           f"  Kernel driver in use: {driver or '(none)'}\n"
                           f"  Kernel modules: {modules}",
                       command="lspci -k")]

        if not driver:
            findings.append(Finding(
                id="graphics.no_driver",
                title=f"No kernel driver is bound to the graphics controller ({desc[:50]})",
                category=Category.GRAPHICS, severity=Severity.HIGH,
                summary="The GPU is present but no driver has claimed it, so rendering falls back to software.",
                root_cause="Driver module failed to load, is blacklisted, or is missing firmware.",
                impact="Sluggish desktop, no hardware video decoding, high CPU usage.",
                evidence=ev, confidence=Confidence.DIRECT,
                recommendations=[
                    "Check 'dmesg | grep -i -E \"amdgpu|radeon|firmware\"' for a load failure.",
                    "Ensure the linux-firmware package is installed.",
                ],
                manual=True))
        elif is_amd and driver == "radeon" and "amdgpu" in modules:
            findings.append(Finding(
                id="graphics.amd_driver_choice",
                title="AMD GPU is using the older 'radeon' driver instead of 'amdgpu'",
                category=Category.GRAPHICS, severity=Severity.LOW,
                summary=(f"The controller is bound to the legacy 'radeon' driver, although "
                         f"'amdgpu' is available for it. The two differ in power management, "
                         f"TearFree support and suspend reliability."),
                root_cause=("For AMD 'Stoney Ridge' and similar parts the kernel picks "
                            "'radeon' by default; 'amdgpu' support for them is present but "
                            "not always selected automatically."),
                impact="Possible screen tearing, weaker power management, occasional suspend problems.",
                evidence=ev,
                confidence=Confidence.DIRECT,
                recommendations=[
                    "Switching drivers is a kernel-parameter change (radeon.si_support=0 "
                    "amdgpu.si_support=1) and can cause a black screen if it does not apply "
                    "to your exact GPU, so it is left as a manual step.",
                    "Try it from the GRUB menu first (press 'e' at boot) before making it permanent.",
                ],
                manual=True, reboot_required=True))
        elif is_amd and driver == "amdgpu":
            findings.append(Finding(
                id="graphics.amd_driver_ok",
                title=f"AMD GPU is using the modern 'amdgpu' driver",
                category=Category.GRAPHICS, severity=Severity.OK,
                summary=f"{desc[:60]} is bound to the amdgpu driver, which is the correct "
                        f"modern driver for this hardware.",
                evidence=ev, confidence=Confidence.DIRECT))

    # ------------------------------------------------- software rendering
    renderer, rsrc = renderer_info()
    facts["renderer"] = renderer
    if renderer:
        if re.search(r"llvmpipe|softpipe|swrast|Software Rasterizer", renderer, re.I):
            findings.append(Finding(
                id="graphics.software_rendering",
                title=f"Graphics are being rendered by the CPU, not the GPU ({renderer.split(',')[0][:40]})",
                category=Category.GRAPHICS, severity=Severity.HIGH,
                summary=(f"The OpenGL renderer is '{renderer.split(',')[0]}'. That is a "
                         f"software rasteriser: every frame is drawn by the CPU."),
                root_cause=("Either the GPU driver is not loaded, the DISPLAY session started "
                            "before the driver was ready, LIBGL_ALWAYS_SOFTWARE is set, or "
                            "'nomodeset' is in the kernel command line."),
                impact="Stuttering video, laggy window movement, high CPU usage, fan noise.",
                evidence=[Evidence(source=rsrc, detail=f"OpenGL renderer: {renderer}",
                                   command="glxinfo -B"),
                          Evidence(source="environment",
                                   detail=f"LIBGL_ALWAYS_SOFTWARE={os.environ.get('LIBGL_ALWAYS_SOFTWARE', '(unset)')}",
                                   command="echo $LIBGL_ALWAYS_SOFTWARE")],
                confidence=Confidence.DIRECT,
                recommendations=[
                    "Confirm a driver is bound to the GPU (see above) and that 'nomodeset' is not set.",
                    "Ensure xserver-xorg-video-amdgpu and mesa drivers are installed.",
                    "Log out and back in after changing drivers.",
                ],
                manual=True))

    # ------------------------------------------------------ DRI devices
    dri_ok = ex.exists("/dev/dri/renderD128") or ex.exists("/dev/dri/card0")
    facts["dri"] = dri_ok
    if not dri_ok and not renderer:
        findings.append(Finding(
            id="graphics.no_dri",
            title="No GPU device nodes (/dev/dri) are available",
            category=Category.GRAPHICS, severity=Severity.MEDIUM,
            summary="Without /dev/dri nodes, applications cannot use the GPU at all.",
            root_cause="Kernel modesetting is disabled or the driver did not initialise.",
            evidence=[Evidence(source="/dev/dri", detail="no card0 or renderD128 found",
                               command="ls /dev/dri")],
            confidence=Confidence.DIRECT, manual=True,
            recommendations=["Check 'dmesg | grep -i drm' and that a driver is bound to the GPU."]))

    # ------------------------------------------------- firmware failures
    fw = match_lines(logs, [r"failed to load firmware",
                            r"Direct firmware load for .* failed",
                            r"amdgpu \S+: .*firmware",
                            r"radeon \S+: .*firmware"], limit=5)
    if fw:
        findings.append(Finding(
            id="graphics.firmware_missing",
            title="The kernel failed to load GPU firmware",
            category=Category.GRAPHICS, severity=Severity.HIGH,
            summary=("The graphics driver asked for firmware files that are not present, so "
                     "it cannot initialise the GPU properly."),
            root_cause="The linux-firmware package is missing or out of date for this kernel.",
            impact="Software rendering or a black screen; the GPU runs unreliably.",
            evidence=[Evidence(source="kernel log", detail=line[:180], raw=line,
                               command="dmesg | grep -i firmware") for _p, line in fw],
            confidence=Confidence.DIRECT, needs_network=True,
            recommendations=["Install or update the firmware package: sudo apt install --reinstall linux-firmware"],
            manual=True))

    # ------------------------------------------------------ Xorg errors
    xlog, xerrs = xorg_log_errors()
    if xerrs:
        findings.append(Finding(
            id="graphics.xorg_errors",
            title=f"The X server logged {len(xerrs)} error(s) at startup",
            category=Category.GRAPHICS, severity=Severity.MEDIUM,
            summary=f"{xlog} contains {len(xerrs)} lines marked (EE).",
            root_cause="A failed driver or extension load during X startup.",
            impact="Missing acceleration or input features.",
            evidence=[Evidence(source=xlog, detail=e[:180], raw="\n".join(xerrs),
                               command=f"grep '(EE)' {xlog}")],
            confidence=Confidence.DIRECT, manual=True,
            recommendations=[f"Review the file: {xlog}"]))

    # ------------------------------------------------- Xfce compositing
    comp = xfconf_get("xfwm4", "/general/use_compositing")
    facts["xfce_compositing"] = comp
    if comp is None:
        facts["xfce_compositing_note"] = "xfconf-query unavailable or no X session"
    elif comp.lower() == "true":
        findings.append(Finding(
            id="graphics.compositing_on",
            title="Window compositing is enabled in Xfce",
            category=Category.GRAPHICS, severity=Severity.LOW,
            summary=("Xfce is drawing every window through an off-screen buffer. On an "
                     "integrated AMD GPU with a mechanical disk this adds latency to window "
                     "movement and video playback."),
            root_cause="Compositing is enabled by default in Xfce for visual effects.",
            impact="Noticeable lag when dragging windows, resizing, or playing video.",
            evidence=[Evidence(source="xfconf-query -c xfwm4 -p /general/use_compositing",
                               detail="use_compositing = true",
                               command="xfconf-query -c xfwm4 -p /general/use_compositing")],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Turning compositing off is instantly reversible and usually the single "
                "quickest way to make the desktop feel snappier.",
                "Settings > Window Manager Tweaks > Compositor, or use the repair below.",
            ],
            repair_ids=["xfce.compositing_off"]))

    # ------------------------------------------------ VRAM / GPU load
    vram = None
    for card in ex.listdir("/sys/class/drm"):
        for attr in ("device/mem_info_vram_total", "device/mem_info_vram_used"):
            v = ex.read_text(f"/sys/class/drm/{card}/{attr}")
            if v and v.strip().isdigit():
                if attr.endswith("total"):
                    vram = int(v.strip())
    if vram:
        facts["vram_bytes"] = vram
        if vram < 512 * 1024 * 1024:
            findings.append(Finding(
                id="graphics.small_vram",
                title=f"GPU memory is only {vram // (1024 * 1024)} MB",
                category=Category.GRAPHICS, severity=Severity.LOW,
                summary="Integrated graphics reserve a small slice of system RAM (which is itself only 4 GB).",
                root_cause="Integrated GPU without dedicated VRAM.",
                impact="Heavy browser pages and video can force the driver to shuffle memory.",
                evidence=[Evidence(source="/sys/class/drm/card0/device/mem_info_vram_total",
                                   detail=f"{vram // (1024 * 1024)} MB",
                                   command="cat /sys/class/drm/card0/device/mem_info_vram_total")],
                confidence=Confidence.MEASURED, manual=True,
                recommendations=["Keep the number of open browser tabs modest."]))

    return result("graphics", "Graphics, drivers and compositing", Category.GRAPHICS,
                  findings, facts=facts)
