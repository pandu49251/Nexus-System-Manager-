"""
nexus_doctor.checks.keyboard_input
==================================

Keyboard, touchpad and X input configuration.

"My keyboard does not work properly" has a surprisingly large number of very
different causes, and guessing between them is how people end up replacing
hardware that is fine.  This module separates them into evidence-backed
categories:

1.  **Layout mismatch** - keys type the wrong characters.  Detected by
    comparing the active XKB layout with the system locale and with
    ``/etc/default/keyboard``.
2.  **Key repeat** - keys feel unresponsive or repeat far too slowly.  The X11
    default (660 ms delay, 25 repeats/s) is set decades-old and is measurably
    slower than most typists expect.
3.  **Stuck modifier** - Shift/Ctrl/Alt appears to be held down permanently, so
    typing produces shortcuts or capitals.  We prove it by sampling the live
    X input state twice with a pause in between: a key reported "down" in both
    samples, with nobody typing, is genuinely stuck.
4.  **Device disabled in X** - ``xinput`` reports the keyboard as disabled.
5.  **PS/2 controller faults** - ``i8042``/``atkbd`` errors in the kernel log,
    which on IdeaPad laptops usually need a kernel parameter to work around.
6.  **Accessibility features** - Sticky Keys / Slow Keys make a working
    keyboard behave oddly.
7.  **Not a keyboard problem at all** - input lag caused by CPU or disk
    saturation.  We cross-check the measured iowait and load, because typing
    lag while the disk LED is lit has a completely different fix.
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
from .common import match_lines, result

# X11 (evdev) keycode -> human-readable key name, for stuck-key reporting.
KEY_NAMES = {
    22: "BackSpace", 23: "Tab", 36: "Return", 37: "Control_L", 50: "Shift_L",
    62: "Shift_R", 64: "Alt_L", 65: "space", 66: "Caps_Lock", 77: "Num_Lock",
    105: "Control_R", 108: "Alt_R", 133: "Super_L (Windows key)",
    134: "Super_R", 135: "Menu", 9: "Escape",
}
MODIFIER_CODES = {37, 50, 62, 64, 105, 108, 133, 134, 66, 77}

# Locale country -> the keyboard layout a user in that country usually wants.
LOCALE_LAYOUT = {
    "GB": "gb", "US": "us", "IN": "in", "DE": "de", "FR": "fr", "ES": "es",
    "IT": "it", "BR": "br", "RU": "ru", "JP": "jp", "KR": "kr", "CN": "cn",
    "PT": "pt", "PL": "pl", "NL": "nl", "SE": "se", "NO": "no", "DK": "dk",
    "FI": "fi", "CH": "ch", "AT": "at", "BE": "be", "CZ": "cz", "TR": "tr",
    "UA": "ua", "GR": "gr", "IL": "il", "TH": "th", "VN": "vn", "ID": "id",
    "ZA": "za", "AU": "au", "CA": "ca", "MX": "latam", "AR": "latam",
}


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------


def input_devices() -> List[Dict[str, object]]:
    """Parse /proc/bus/input/devices into structured records."""
    out: List[Dict[str, object]] = []
    text = ex.read_text("/proc/bus/input/devices")
    if not text:
        return out
    block: Dict[str, object] = {}
    for line in text.splitlines():
        if not line.strip():
            if block:
                out.append(block)
                block = {}
            continue
        tag, _, rest = line.partition(":")
        tag = tag.strip()
        rest = rest.strip()
        if tag == "N":
            block["name"] = rest.strip('"')
        elif tag == "H":
            block["handlers"] = rest.split()
        elif tag == "S":
            block["sysfs"] = rest
        elif tag == "P":
            block["phys"] = rest
        elif tag == "B":
            key, _, val = rest.partition("=")
            block.setdefault("bits", {})[key] = val  # type: ignore[index]
    if block:
        out.append(block)
    return out


def keyboards(devices: List[Dict[str, object]]) -> List[Dict[str, object]]:
    out = []
    for d in devices:
        name = str(d.get("name", ""))
        handlers = d.get("handlers") or []
        bits = d.get("bits") or {}
        is_kbd = ("kbd" in handlers) or re.search(r"keyboard|kbd", name, re.I)
        has_keys = isinstance(bits, dict) and bool(bits.get("KEY"))
        if is_kbd and has_keys and "input" in str(d.get("sysfs", "")):
            out.append(d)
        elif is_kbd:
            out.append(d)
    return out


def touchpads(devices: List[Dict[str, object]]) -> List[Dict[str, object]]:
    out = []
    for d in devices:
        name = str(d.get("name", "")).lower()
        handlers = d.get("handlers") or []
        if ("mouse" in handlers or "event" in " ".join(handlers)) and re.search(
                r"touchpad|trackpoint|synaptics|elan|glidepoint|clickpad", name):
            out.append(d)
    return out


XINPUT_LINE = re.compile(r"^\s*[↳⎜⎡⎣]?\s*(?P<name>.+?)\s+id=(?P<id>\d+)\s*(?:\[(?P<cls>.*?)\])?\s*$")


def xinput_devices() -> List[Dict[str, str]]:
    if not ex.have_tool("xinput") or not privileges.has_gui_session():
        return []
    r = privileges.run_as_user(["xinput", "list"], timeout=10)
    if not r.ok:
        return []
    out: List[Dict[str, str]] = []
    for line in r.lines:
        m = XINPUT_LINE.match(line.replace("\t", " ").strip())
        if m and m.group("id"):
            name = m.group("name").strip(" ↳")
            out.append({"id": m.group("id"), "name": name,
                        "class": (m.group("cls") or "").strip()})
    return out


def xinput_is_enabled(device_id: str) -> Optional[bool]:
    r = privileges.run_as_user(["xinput", "list-props", device_id], timeout=10)
    if not r.ok:
        return None
    m = re.search(r"Device Enabled.*?:\s*(\d)", r.out, re.S)
    if m:
        return m.group(1) == "1"
    return None


def xinput_down_keys(device_id: str) -> List[int]:
    """Keycodes currently reported as physically held down."""
    r = privileges.run_as_user(["xinput", "--query-state", device_id], timeout=10)
    if not r.ok:
        return []
    down: List[int] = []
    for line in r.lines:
        m = re.match(r"\s*key\[(\d+)\]\s*=\s*down", line)
        if m:
            down.append(int(m.group(1)))
    return down


def xkb_query() -> Dict[str, str]:
    if not ex.have_tool("setxkbmap") or not privileges.has_gui_session():
        return {}
    r = privileges.run_as_user(["setxkbmap", "-query"], timeout=10)
    if not r.ok:
        return {}
    out: Dict[str, str] = {}
    for line in r.lines:
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def xset_state() -> Dict[str, Optional[int]]:
    """Parse 'xset q': auto-repeat flag, delay (ms) and rate (repeats/sec)."""
    if not ex.have_tool("xset") or not privileges.has_gui_session():
        return {}
    r = privileges.run_as_user(["xset", "q"], timeout=10)
    if not r.ok:
        return {}
    out: Dict[str, Optional[int]] = {}
    m = re.search(r"auto repeat:\s*(\w+)", r.out, re.I)
    if m:
        out["auto_repeat"] = 1 if m.group(1).lower().startswith("on") else 0
    m = re.search(r"auto repeat delay:\s*(\d+)\s+repeat rate:\s*(\d+)", r.out, re.I)
    if m:
        out["delay_ms"] = int(m.group(1))
        out["rate_hz"] = int(m.group(2))
    return out


def xfce_accessibility() -> Dict[str, str]:
    """Read Xfce's accessibility (Sticky/Slow/Bounce keys) settings."""
    if not ex.have_tool("xfconf-query") or not privileges.has_gui_session():
        return {}
    out: Dict[str, str] = {}
    for prop in ("StickyKeys", "SlowKeys", "BounceKeys", "MouseKeys"):
        r = privileges.run_as_user(["xfconf-query", "-c", "accessibility", "-p", f"/{prop}"],
                                   timeout=6)
        if r.ok and r.first.strip():
            out[prop] = r.first.strip()
    return out


def default_keyboard_file() -> Dict[str, str]:
    return {k: v for k, v in
            ((l.split("=", 1)[0].strip(), l.split("=", 1)[1].strip().strip('"'))
             for l in ex.read_lines("/etc/default/keyboard", [])
             if "=" in l and not l.strip().startswith("#"))}


def locale_country() -> str:
    for var in ("LC_ALL", "LC_CTYPE", "LANG"):
        val = os.environ.get(var, "")
        m = re.match(r"^[a-z]{2,3}_([A-Z]{2})", val)
        if m:
            return m.group(1)
    for line in ex.read_lines("/etc/default/locale", []):
        if "=" in line:
            _k, _, v = line.partition("=")
            m = re.match(r"^[a-z]{2,3}_([A-Z]{2})", v.strip().strip('"'))
            if m:
                return m.group(1)
    return ""


# --------------------------------------------------------------------------
# Check
# --------------------------------------------------------------------------


@register("keyboard_input", "Keyboard and input devices", Category.INPUT, priority=41,
          description="Keyboard layout, key repeat, stuck keys, PS/2 errors, touchpad")
def check_keyboard_input(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}
    logs = ctx.shared_get("log.lines") or []

    devices = input_devices()
    kbds = keyboards(devices)
    pads = touchpads(devices)
    facts["input_devices"] = [{"name": d.get("name"), "handlers": d.get("handlers")}
                              for d in devices]
    facts["keyboards"] = [d.get("name") for d in kbds]
    facts["touchpads"] = [d.get("name") for d in pads]

    # ------------------------------------------------ is a keyboard there?
    if not kbds:
        findings.append(Finding(
            id="input.keyboard_missing",
            title="No keyboard device was detected",
            category=Category.INPUT, severity=Severity.CRITICAL,
            summary=("The kernel is not reporting any keyboard input device. Without one, "
                     "the X server has nothing to read keystrokes from."),
            root_cause=("The PS/2 controller driver (i8042/atkbd) did not initialise, the "
                        "keyboard ribbon cable is disconnected, or the device is disabled "
                        "in firmware setup."),
            impact="No typing is possible (except possibly via an on-screen keyboard).",
            evidence=[Evidence(source="/proc/bus/input/devices",
                               detail="no device whose handlers include 'kbd'",
                               raw=(ex.read_text("/proc/bus/input/devices") or "")[:800],
                               command="cat /proc/bus/input/devices")],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Try an external USB keyboard: if it works, the internal keyboard or its "
                "cable is at fault.",
                "Check the kernel log: dmesg | grep -i i8042",
                "On IdeaPad models the kernel parameters 'i8042.nopnp i8042.reset i8042.nomux' "
                "fix many detection failures (see the manual steps below).",
            ],
            manual=True))

    kbd_ev = [Evidence(source="/proc/bus/input/devices",
                       detail="; ".join(f"{d.get('name')} (handlers: {' '.join(d.get('handlers') or [])})"
                                        for d in kbds) or "none",
                       raw="\n".join(f"N: Name=\"{d.get('name')}\"\nH: Handlers={' '.join(d.get('handlers') or [])}"
                                     for d in kbds) or "(none)",
                       command="cat /proc/bus/input/devices")]

    # ------------------------------------------------------- X device state
    xdevs = xinput_devices()
    facts["xinput"] = xdevs
    xkbd = [d for d in xdevs if "keyboard" in d["class"].lower()][:4]

    for d in xkbd:
        if "Virtual core" in d["name"] or "XTEST" in d["name"]:
            continue
        enabled = xinput_is_enabled(d["id"])
        if enabled is False:
            findings.append(Finding(
                id="input.keyboard_disabled",
                title=f"Keyboard '{d['name']}' is disabled in the X server",
                category=Category.INPUT, severity=Severity.HIGH,
                summary=("The keyboard exists but X has been told to ignore it, so it "
                         "produces no keystrokes."),
                root_cause="The device was disabled with 'xinput --disable' (or a tool did it).",
                impact="Typing does nothing.",
                evidence=[Evidence(source=f"xinput list-props {d['id']}",
                                   detail=f"Device Enabled = 0 for {d['name']} (id {d['id']})",
                                   command=f"xinput list-props {d['id']}")],
                confidence=Confidence.DIRECT,
                recommendations=[f"Re-enable it with: xinput --enable {d['id']}"],
                repair_ids=["input.enable_keyboard"],
                data={"device_id": d["id"]},
            ))

    # --------------------------------------------------------- stuck keys
    stuck: List[Tuple[str, int]] = []
    physical = [d for d in xkbd
                if "Virtual core" not in d["name"] and "XTEST" not in d["name"]]
    # Real keyboards first: power buttons and video buses also expose key
    # classes and would otherwise be sampled instead of the actual keyboard.
    physical.sort(key=lambda d: (0 if "keyboard" in d["name"].lower() else 1, d["name"]))
    targets = physical[:2] or [d for d in xkbd if "Virtual core keyboard" in d["name"]][:1]
    seen: Dict[int, str] = {}
    for d in targets:
        first = set(xinput_down_keys(d["id"]))
        if not first:
            continue
        time.sleep(2.0)
        second = set(xinput_down_keys(d["id"]))
        for code in sorted(first & second):
            seen.setdefault(code, d["name"])
    stuck = [(seen[code], code) for code in sorted(seen)]
    if stuck:
        described = ", ".join(f"{KEY_NAMES.get(c, f'keycode {c}')}" for _d, c in stuck)
        findings.append(Finding(
            id="input.stuck_key",
            title=f"A key appears to be stuck down: {described}",
            category=Category.INPUT, severity=Severity.MEDIUM,
            summary=(f"The X server reports {described} as physically held down in two "
                     f"separate samples taken 2 seconds apart."),
            root_cause=("A modifier key is logically stuck. This is common on IdeaPad PS/2 "
                        "keyboards after a suspend/resume cycle, or when a keycap is "
                        "physically obstructed."),
            impact=("Typing produces capitals, shortcuts or menu actions instead of "
                    "characters - it looks like the keyboard is broken."),
            evidence=[Evidence(source="xinput --query-state <id> (two samples, 2 s apart)",
                               detail=f"keys down in both samples: {described}",
                               raw="\n".join(f"device={d} keycode={c}" for d, c in stuck),
                               command="xinput --query-state <keyboard id>")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "Press and release each modifier (Shift, Ctrl, Alt, Super) once - this "
                "usually clears the stuck state.",
                "If it recurs, add 'i8042.reset' to the kernel command line (see manual steps), "
                "which resets the PS/2 controller at boot.",
                "Check for a physically jammed keycap or debris.",
            ],
            manual=True,
            data={"keys": [c for _d, c in stuck]},
        ))

    # --------------------------------------------------------- key repeat
    xs = xset_state()
    facts["xset"] = xs
    if xs:
        if xs.get("auto_repeat") == 0:
            findings.append(Finding(
                id="input.autorepeat_off",
                title="Key auto-repeat is switched off",
                category=Category.INPUT, severity=Severity.MEDIUM,
                summary="Holding a key produces a single character instead of repeating.",
                root_cause="Auto-repeat was disabled with 'xset -r' or by an application.",
                impact="Tedious typing; many users read this as a broken keyboard.",
                evidence=[Evidence(source="xset q", detail="auto repeat: off",
                                   command="xset q")],
                confidence=Confidence.DIRECT,
                recommendations=["Turn it back on: xset r on (repair below sets a sane rate too)."],
                repair_ids=["input.keyrepeat"],
            ))
        delay = xs.get("delay_ms")
        rate = xs.get("rate_hz")
        if delay is not None and rate is not None:
            facts["repeat_delay_ms"] = delay
            facts["repeat_rate_hz"] = rate
            # X11 defaults: delay 660 ms, rate 25 Hz. A modern, comfortable
            # setting is ~250 ms delay and 30-40 repeats/second.
            if delay >= 500 or rate <= 25:
                findings.append(Finding(
                    id="input.repeat_rate",
                    title=f"Key repeat is set to the very slow X11 default ({delay} ms delay, {rate}/s)",
                    category=Category.INPUT, severity=Severity.MEDIUM,
                    summary=(f"Held keys wait {delay} ms before repeating and then repeat only "
                             f"{rate} times per second. The X11 defaults date from the 1980s "
                             f"and feel unresponsive to most typists."),
                    root_cause=("The X server's default key-repeat timing is inherited; "
                                "Xfce does not change it unless told to."),
                    impact=("Typing feels laggy, backspacing through a word is slow, and the "
                            "keyboard seems not to keep up."),
                    evidence=[Evidence(source="xset q",
                                       detail=f"auto repeat delay: {delay} ms, repeat rate: {rate} per second",
                                       raw="\n".join(l for l in
                                                     (privileges.run_as_user(["xset", "q"]).out or "")
                                                     .splitlines()
                                                     if "repeat" in l.lower()),
                                       command="xset q")],
                    confidence=Confidence.MEASURED,
                    recommendations=[
                        "Set a responsive rate: xset r rate 250 35 (250 ms before repeating, "
                        "then 35 repeats per second), and persist it across logins.",
                    ],
                    repair_ids=["input.keyrepeat"],
                    data={"delay_ms": delay, "rate_hz": rate},
                ))

    # ------------------------------------------------------------- layout
    xkb = xkb_query()
    facts["xkb"] = xkb
    kbdfile = default_keyboard_file()
    facts["default_keyboard"] = kbdfile
    if xkb:
        layout = xkb.get("layout", "")
        variant = xkb.get("variant", "")
        model = xkb.get("model", "")
        options = xkb.get("options", "")
        facts["layout"] = layout
        ev = [Evidence(source="setxkbmap -query",
                       detail=f"rules={xkb.get('rules','')} model={model} layout={layout} "
                              f"variant={variant} options={options}",
                       raw="\n".join(f"{k}: {v}" for k, v in xkb.items()),
                       command="setxkbmap -query")]
        if kbdfile:
            ev.append(Evidence(source="/etc/default/keyboard",
                               detail="; ".join(f"{k}={v}" for k, v in kbdfile.items()),
                               command="cat /etc/default/keyboard"))

        if not layout or layout.lower() in ("(null)", "unknown"):
            findings.append(Finding(
                id="input.layout_unset",
                title="No keyboard layout is configured for the X session",
                category=Category.INPUT, severity=Severity.HIGH,
                summary="setxkbmap reports an empty layout, so keystrokes are mapped with a fallback.",
                root_cause="The XKB configuration is unset or was not applied at session start.",
                impact="Keys may produce unexpected or no characters.",
                evidence=ev, confidence=Confidence.DIRECT,
                recommendations=["Set the layout explicitly (repair below)."],
                repair_ids=["input.layout"],
            ))
        else:
            country = locale_country()
            expected = LOCALE_LAYOUT.get(country)
            mismatch = expected and layout.split(",")[0].strip().lower() != expected
            file_mismatch = (kbdfile.get("XKBLAYOUT", "") and
                             kbdfile["XKBLAYOUT"].split(",")[0].strip().lower()
                             != layout.split(",")[0].strip().lower())
            if mismatch or file_mismatch:
                sev = Severity.MEDIUM if mismatch else Severity.LOW
                why = (f"Your system locale implies the '{expected}' layout, but the session "
                       f"is using '{layout}'." if mismatch else
                       f"The login-screen configuration ({kbdfile.get('XKBLAYOUT')}) differs "
                       f"from the active session layout ({layout}).")
                findings.append(Finding(
                    id="input.layout_mismatch",
                    title=(f"Keyboard layout is '{layout}', but '{expected}' is the layout "
                           f"for your region" if mismatch else
                           f"Session layout '{layout}' differs from the login-screen "
                           f"configuration '{kbdfile.get('XKBLAYOUT')}'"),
                    category=Category.INPUT, severity=sev,
                    summary=(f"{why} Keys that produce punctuation and symbols (such as "
                             f"@ \" # £ ₹) are the ones that differ between layouts, which is "
                             f"why only some keys appear to be wrong."),
                    root_cause=("The layout chosen at installation does not match the region "
                                "selected afterwards, or the session setting was changed later."),
                    impact="Some keys type the wrong characters - often reported as 'broken keys'.",
                    evidence=ev + ([Evidence(source="/etc/default/locale or $LANG",
                                             detail=f"locale country: {country} -> expected layout '{expected}'",
                                             command="echo $LANG")] if mismatch else []),
                    confidence=Confidence.INFERRED,
                    recommendations=[
                        f"Switch to the '{expected or kbdfile.get('XKBLAYOUT')}' layout, or "
                        f"deliberately keep '{layout}' if that is what you want.",
                        "Settings > Keyboard > Layout, or use the repair below.",
                    ],
                    repair_ids=["input.layout"],
                    data={"layout": layout,
                          "expected": expected or kbdfile.get("XKBLAYOUT")},
                ))
            else:
                findings.append(Finding(
                    id="input.layout_ok",
                    title=f"Keyboard layout is '{layout}' ({model})",
                    category=Category.INPUT, severity=Severity.OK,
                    summary=f"Active layout '{layout}' matches the system configuration.",
                    evidence=ev, confidence=Confidence.MEASURED))

    # --------------------------------------------------- PS/2 controller
    atkbd = match_lines(logs, [
        r"i8042: PNP: No PS/2 controller found",
        r"i8042: No controller found",
        r"atkbd serio\d+: Spurious ACK",
        r"atkbd serio\d+: Unknown key",
        r"i8042: probe of \S+ failed",
        r"serio: i8042",
        r"atkbd: probe of",
    ], limit=5)
    if atkbd:
        serious = any(re.search(r"No PS/2 controller|No controller found|probe .* failed|Spurious ACK",
                                line, re.I) for _p, line in atkbd)
        findings.append(Finding(
            id="input.ps2_errors",
            title="The PS/2 keyboard controller reported errors",
            category=Category.INPUT,
            severity=Severity.HIGH if serious else Severity.MEDIUM,
            summary=("The kernel's i8042/atkbd driver logged problems talking to the "
                     "keyboard controller. On IdeaPad laptops this typically shows up as "
                     "random repeated characters, missing keystrokes, or a keyboard that "
                     "stops responding after suspend."),
            root_cause=("The PS/2 controller is not being detected reliably by the ACPI "
                        "tables, or the controller is left in a bad state after a "
                        "suspend/resume cycle."),
            impact="Missed, repeated or stuck keystrokes.",
            evidence=[Evidence(source="kernel log", detail=line[:180], raw=line,
                               command="dmesg | grep -i -E 'i8042|atkbd'")
                      for _p, line in atkbd],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Add the PS/2 workaround to the kernel command line: edit /etc/default/grub, "
                'set GRUB_CMDLINE_LINUX_DEFAULT="quiet splash i8042.reset i8042.nomux i8042.nopnp", '
                "run 'sudo update-grub' and reboot.",
                "If the problem only appears after suspend, test the parameters first by "
                "pressing 'e' at the GRUB menu and adding them to the linux line.",
            ],
            manual=True, reboot_required=True))

    # ------------------------------------------------ input driver present
    has_libinput = f.has_package("xserver-xorg-input-libinput")
    has_evdev = f.has_package("xserver-xorg-input-evdev")
    has_synaptics = f.has_package("xserver-xorg-input-synaptics")
    facts["input_drivers"] = {"libinput": has_libinput, "evdev": has_evdev,
                              "synaptics": has_synaptics}
    if not has_libinput and not has_evdev:
        findings.append(Finding(
            id="input.no_driver",
            title="No X input driver package is installed",
            category=Category.INPUT, severity=Severity.CRITICAL,
            summary=("Neither xserver-xorg-input-libinput nor xserver-xorg-input-evdev is "
                     "installed. Without one, X cannot read the keyboard or touchpad."),
            root_cause="The input driver package is missing (unusual unless it was removed).",
            impact="Keyboard and touchpad dead in the graphical session.",
            evidence=[Evidence(source="package database",
                               detail="xserver-xorg-input-libinput: not installed; "
                                      "xserver-xorg-input-evdev: not installed",
                               command="dpkg -l | grep xserver-xorg-input")],
            confidence=Confidence.MEASURED, needs_network=True,
            recommendations=["From a console: sudo apt install xserver-xorg-input-libinput"],
            manual=True))

    # ------------------------------------------------ Xorg input errors
    from .graphics import xorg_log_errors
    xlog, xerrs = xorg_log_errors()
    if xerrs:
        input_errs = [e for e in xerrs if re.search(
            r"keyboard|kbd|input|libinput|evdev|synaptics", e, re.I)]
        if input_errs:
            findings.append(Finding(
                id="input.xorg_errors",
                title=f"The X server logged {len(input_errs)} keyboard/input error(s)",
                category=Category.INPUT, severity=Severity.MEDIUM,
                summary=f"{xlog} contains input-related (EE) lines.",
                root_cause="A failed input module or device open at X startup.",
                evidence=[Evidence(source=xlog, detail=e[:180], raw="\n".join(input_errs),
                                   command=f"grep -E '\\(EE\\)' {xlog}")],
                confidence=Confidence.DIRECT, manual=True,
                recommendations=[f"Inspect: {xlog}"]))

    # ------------------------------------------------- accessibility keys
    acc = xfce_accessibility()
    facts["accessibility"] = acc
    enabled_acc = {k: v for k, v in acc.items() if str(v).lower() == "true"}
    if enabled_acc:
        findings.append(Finding(
            id="input.accessibility_on",
            title=f"Accessibility key features are enabled: {', '.join(enabled_acc)}",
            category=Category.INPUT, severity=Severity.MEDIUM,
            summary=("Sticky Keys / Slow Keys change how the keyboard behaves: Slow Keys "
                     "ignores brief presses unless they are held, which feels exactly like "
                     "'the keyboard misses my keystrokes'."),
            root_cause="Xfce accessibility options were enabled (sometimes accidentally, by holding Shift for 8 seconds).",
            impact="Keystrokes appear to be dropped; modifier keys behave oddly.",
            evidence=[Evidence(source="xfconf-query -c accessibility",
                               detail="; ".join(f"{k} = {v}" for k, v in acc.items()),
                               command="xfconf-query -c accessibility -l")],
            confidence=Confidence.DIRECT,
            recommendations=["Turn them off in Settings > Accessibility > Keyboard, or with xfconf-query."],
            manual=True,
            data=enabled_acc,
        ))

    # ------------------------------------------ input lag from system load
    iowait = ctx.shared_get("cpu.iowait_pct")
    load1 = f.loadavg[0] if f.loadavg else 0.0
    if (iowait is not None and iowait >= 15) or load1 > max(3.0, f.cpu_cores * 2):
        findings.append(Finding(
            id="input.lag_from_load",
            title="Typing lag may be a symptom of system load, not a keyboard fault",
            category=Category.INPUT, severity=Severity.MEDIUM,
            summary=(f"Measured iowait {iowait}% and load {load1:.2f}. When the system is "
                     f"busy, keystrokes are queued behind other work, so characters appear "
                     f"late or in bursts - which feels like a keyboard problem."),
            root_cause="Input events are delayed by CPU or disk saturation rather than by the keyboard hardware.",
            impact="Characters appear a moment after typing; bursts of repeated letters.",
            evidence=[Evidence(source="/proc/stat, /proc/loadavg",
                               detail=f"iowait={iowait}%, load1={load1:.2f} on {f.cpu_cores} core(s)",
                               command="cat /proc/loadavg")],
            confidence=Confidence.INFERRED,
            recommendations=[
                "Fix the underlying load first (see the Processor and Services checks), then "
                "re-evaluate the keyboard.",
            ],
            data={"iowait": iowait, "load1": load1},
        ))

    # ------------------------------------------------------ touchpad note
    if pads:
        facts.setdefault("notes", {})
        driver = "libinput" if has_libinput else ("synaptics" if has_synaptics else "unknown")
        findings.append(Finding(
            id="input.touchpad_present",
            title=f"Touchpad detected: {pads[0].get('name')}",
            category=Category.INPUT, severity=Severity.INFO,
            summary=f"The touchpad is present and handled by the {driver} driver.",
            evidence=[Evidence(source="/proc/bus/input/devices",
                               detail=f"{pads[0].get('name')} (handlers: "
                                      f"{' '.join(pads[0].get('handlers') or [])})",
                               command="cat /proc/bus/input/devices")],
            confidence=Confidence.DIRECT, manual=True))

    return result("keyboard_input", "Keyboard and input devices", Category.INPUT,
                  findings, facts=facts)
