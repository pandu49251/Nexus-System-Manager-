"""
nexus_doctor.repairs.desktop_input
==================================

Repairs for the desktop session, the keyboard, and package-database integrity.

These all run inside the user's graphical session (``xset``, ``xfconf-query``,
``setxkbmap``).  When the application itself is running as root, the commands
are re-executed as the invoking user with the session environment recovered
from ``/proc``, because X settings must be changed for the session, not for
root.
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

from ..core import executil as ex
from ..core import privileges
from ..core.models import Repair, RepairOutcome, Risk
from ..core.repairer import RepairContext, register_repair

HOME = privileges.user_home()
AUTOSTART_DIR = os.path.join(HOME, ".config/autostart")


def _desktop_entry(name: str, exec_line: str, comment: str) -> str:
    return ("[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={name}\n"
            f"Comment={comment}\n"
            f"Exec={exec_line}\n"
            "Terminal=false\n"
            "OnlyShowIn=XFCE;\n"
            "X-Nexus-System-Doctor=true\n")


# --------------------------------------------------------------------------
# Xfce compositing
# --------------------------------------------------------------------------


class XfceCompositingRepair(Repair):
    """Turn off Xfce's window compositor."""

    id = "xfce.compositing_off"
    title = "Turn off window compositing in Xfce"
    description = ("Compositing redraws every window through an off-screen buffer. On an "
                   "integrated AMD GPU with a mechanical disk it adds visible lag when "
                   "moving windows or playing video. Instantly reversible.")
    risk = Risk.LOW
    requires_gui = True
    fixes = ["graphics.compositing_on"]

    def _current(self, ctx: RepairContext) -> Optional[str]:
        r = ctx.run_user(["xfconf-query", "-c", "xfwm4", "-p", "/general/use_compositing"],
                         timeout=10)
        return r.first.strip() if r.ok else None

    def available(self, ctx: RepairContext) -> bool:
        return self._current(ctx) == "true"

    def why(self, ctx: RepairContext) -> str:
        return ("Removes the per-frame compositing overhead; windows and video stop "
                "stuttering on this GPU.")

    def steps(self, ctx: RepairContext) -> List[str]:
        return ["Run: xfconf-query -c xfwm4 -p /general/use_compositing -s false"]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        r = ctx.run_user(["xfconf-query", "-c", "xfwm4", "-p",
                          "/general/use_compositing", "-s", "false"], timeout=15)
        return RepairOutcome(r.ok, "compositing disabled" if r.ok else r.err.strip()[:160],
                             commands=["xfconf-query -c xfwm4 -p /general/use_compositing -s false"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        cur = self._current(ctx)
        state = f"xfwm4 use_compositing = {cur}"
        return RepairOutcome(cur == "false", state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Re-enable compositing."""
        ctx.run_user(["xfconf-query", "-c", "xfwm4", "-p",
                      "/general/use_compositing", "-s", "true"], timeout=15)
        return RepairOutcome(self._current(ctx) == "true", "compositing re-enabled")


# --------------------------------------------------------------------------
# Key repeat
# --------------------------------------------------------------------------


class KeyRepeatRepair(Repair):
    """Set a responsive key-repeat rate and persist it across logins."""

    id = "input.keyrepeat"
    title = "Set a responsive key repeat rate"
    description = ("Changes the X11 default (660 ms delay, 25 repeats/s) to 250 ms / 35 per "
                   "second and keeps the setting after a reboot with an autostart entry.")
    risk = Risk.LOW
    requires_gui = True
    fixes = ["input.repeat_rate", "input.autorepeat_off"]

    DELAY = 250
    RATE = 35
    FILE = os.path.join(AUTOSTART_DIR, "nexus-keyboard-repeat.desktop")

    def _state(self, ctx: RepairContext) -> str:
        r = ctx.run_user(["xset", "q"], timeout=10)
        if not r.ok:
            return "unknown"
        m = re.search(r"auto repeat delay:\s*(\d+)\s+repeat rate:\s*(\d+)", r.out)
        return f"delay={m.group(1)}ms rate={m.group(2)}/s" if m else "unknown"

    def available(self, ctx: RepairContext) -> bool:
        return self._state(ctx) != f"delay={self.DELAY}ms rate={self.RATE}/s"

    def why(self, ctx: RepairContext) -> str:
        return (f"Currently {self._state(ctx)}; the X11 default makes typing and "
                f"backspacing feel unresponsive.")

    def steps(self, ctx: RepairContext) -> List[str]:
        return [
            f"Run: xset r rate {self.DELAY} {self.RATE} (takes effect immediately).",
            f"Create {self.FILE} so it is applied again at every login.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        r = ctx.run_user(["xset", "r", "rate", str(self.DELAY), str(self.RATE)], timeout=10)
        ctx.run_user(["xset", "r", "on"], timeout=10)
        ctx.write_file(self.FILE, _desktop_entry(
            "Nexus keyboard repeat",
            f"xset r rate {self.DELAY} {self.RATE}",
            "Apply a responsive key repeat rate (set by Nexus System Doctor)"))
        return RepairOutcome(r.ok,
                             f"key repeat set to {self.DELAY} ms / {self.RATE} per second",
                             commands=[f"xset r rate {self.DELAY} {self.RATE}"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        state = self._state(ctx)
        expected = f"delay={self.DELAY}ms rate={self.RATE}/s"
        persisted = ex.isfile(self.FILE)
        ok = state == expected
        return RepairOutcome(ok,
                             f"{state}{'' if persisted else ' (autostart entry missing)'}",
                             before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Restore the X11 default rate and remove the autostart entry."""
        ctx.run_user(["xset", "r", "rate", "660", "25"], timeout=10)
        ctx.remove_file(self.FILE, backup=False)
        return RepairOutcome(True, "key repeat restored to 660 ms / 25 per second")


# --------------------------------------------------------------------------
# Keyboard layout
# --------------------------------------------------------------------------


class KeyboardLayoutRepair(Repair):
    """Apply the keyboard layout that matches the system's locale."""

    id = "input.layout"
    title = "Set the keyboard layout for your region"
    description = ("Applies the layout implied by your system locale (or the one configured "
                   "in /etc/default/keyboard) to the running session and persists it.")
    risk = Risk.LOW
    requires_gui = True
    fixes = ["input.layout_mismatch", "input.layout_unset"]

    def _current(self, ctx: RepairContext) -> Optional[str]:
        r = ctx.run_user(["setxkbmap", "-query"], timeout=10)
        if not r.ok:
            return None
        for line in r.lines:
            if line.lower().startswith("layout:"):
                return line.split(":", 1)[1].strip()
        return ""

    def _target(self, ctx: RepairContext) -> Optional[str]:
        finding = (ctx.finding("input.layout_mismatch") or
                   ctx.finding("input.layout_unset"))
        if finding:
            want = finding.data.get("expected")
            if want:
                return str(want)
        kbd = {line.split("=", 1)[0]: line.split("=", 1)[1].strip('"')
               for line in ex.read_lines("/etc/default/keyboard", []) if "=" in line}
        return kbd.get("XKBLAYOUT")

    def available(self, ctx: RepairContext) -> bool:
        cur, tgt = self._current(ctx), self._target(ctx)
        return bool(tgt) and cur is not None and cur.split(",")[0] != tgt.split(",")[0]

    def why(self, ctx: RepairContext) -> str:
        return (f"The session is using '{self._current(ctx)}'; switching it to "
                f"'{self._target(ctx)}' makes the punctuation and symbol keys match "
                f"your keyboard.")

    def steps(self, ctx: RepairContext) -> List[str]:
        tgt = self._target(ctx)
        return [
            f"Run: setxkbmap -layout {tgt} (takes effect immediately).",
            "Store the same layout in the Xfce keyboard settings so it persists.",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        tgt = self._target(ctx)
        if not tgt:
            return RepairOutcome(False, "no target layout could be determined")
        r = ctx.run_user(["setxkbmap", "-layout", tgt], timeout=15)
        # Persist in Xfce's settings channel (used by xfce4-keyboard-settings).
        ctx.run_user(["xfconf-query", "-c", "keyboard-layout", "-p",
                      "/Default/XkbLayout", "-s", tgt], timeout=15)
        return RepairOutcome(r.ok, f"keyboard layout set to '{tgt}'",
                             commands=[f"setxkbmap -layout {tgt}"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        cur, tgt = self._current(ctx), self._target(ctx)
        state = f"layout = {cur} (target {tgt})"
        return RepairOutcome(cur is not None and tgt is not None
                             and cur.split(",")[0] == tgt.split(",")[0],
                             state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Restore the previous layout."""
        prev = ctx.param("previous_layout")
        if prev:
            ctx.run_user(["setxkbmap", "-layout", str(prev)], timeout=15)
            return RepairOutcome(True, f"layout restored to '{prev}'")
        return RepairOutcome(False, "the previous layout was not recorded; set it in "
                                    "Settings > Keyboard > Layout")


# --------------------------------------------------------------------------
# Re-enable a disabled keyboard device
# --------------------------------------------------------------------------


class EnableKeyboardRepair(Repair):
    """Re-enable a keyboard that has been disabled in the X server."""

    id = "input.enable_keyboard"
    title = "Re-enable the keyboard in the X server"
    description = ("The keyboard exists but X has been told to ignore it. This sends the "
                   "enable request back to the server.")
    risk = Risk.MEDIUM
    requires_gui = True
    fixes = ["input.keyboard_disabled", "input.keyboard_missing"]

    def _disabled(self, ctx: RepairContext) -> List[dict]:
        from ..checks.keyboard_input import xinput_devices, xinput_is_enabled
        out = []
        for d in xinput_devices():
            if "keyboard" not in d["class"].lower():
                continue
            if "Virtual core" in d["name"] or "XTEST" in d["name"]:
                continue
            if xinput_is_enabled(d["id"]) is False:
                out.append(d)
        return out

    def available(self, ctx: RepairContext) -> bool:
        return bool(self._disabled(ctx))

    def why(self, ctx: RepairContext) -> str:
        return "The keyboard is disabled in X, so it produces no keystrokes."

    def steps(self, ctx: RepairContext) -> List[str]:
        return [f"Run: xinput --enable {d['id']}  ({d['name']})"
                for d in self._disabled(ctx)]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        done = []
        for d in self._disabled(ctx):
            r = ctx.run_user(["xinput", "--enable", d["id"]], timeout=15)
            if r.ok:
                done.append(d["name"])
        return RepairOutcome(bool(done), f"re-enabled: {', '.join(done) or 'nothing'}",
                             commands=[f"xinput --enable {d['id']}"
                                       for d in self._disabled(ctx)])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        still = self._disabled(ctx)
        state = f"disabled keyboards: {', '.join(d['name'] for d in still) or 'none'}"
        return RepairOutcome(not still, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Disable the device again (seldom wanted)."""
        for d in self._disabled(ctx):
            ctx.run_user(["xinput", "--disable", d["id"]], timeout=15)
        return RepairOutcome(True, "keyboard device disabled again")


# --------------------------------------------------------------------------
# Package database
# --------------------------------------------------------------------------


class FixDpkgRepair(Repair):
    """Finish an interrupted package installation."""

    id = "software.fix_dpkg"
    title = "Repair incomplete package installation"
    description = ("Runs 'dpkg --configure -a' to finish packages that were left "
                   "half-installed by an interrupted update. This is the standard, "
                   "distribution-supported repair and touches no user data.")
    risk = Risk.MEDIUM
    requires_root = True
    undoable = False                 # configuring a package cannot be un-done
    fixes = ["software.dpkg_broken"]

    FILE = ""  # no file is written

    def _broken(self, ctx: RepairContext) -> List[str]:
        return [name for name, status in ctx.f.packages.items()
                if status and status != "ii" and status != "rc"]

    def available(self, ctx: RepairContext) -> bool:
        return bool(self._broken(ctx))

    def why(self, ctx: RepairContext) -> str:
        bad = self._broken(ctx)
        return f"{len(bad)} package(s) are half-configured: {', '.join(bad[:5])}."

    def steps(self, ctx: RepairContext) -> List[str]:
        return [
            "Run: dpkg --configure -a  (offline; finishes pending configuration)",
            "Run: apt-get install -f   (fixes missing dependencies; needs the internet)",
        ]

    def apply(self, ctx: RepairContext) -> RepairOutcome:
        r = ctx.run_root(["dpkg", "--configure", "-a"], timeout=300)
        if not r.ok:
            return RepairOutcome(False, f"dpkg --configure -a failed: {r.err.strip()[:200]}",
                                 commands=["dpkg --configure -a"])
        r2 = ctx.run_root(["apt-get", "install", "-f", "-y"], timeout=600)
        return RepairOutcome(True,
                             "dpkg configuration finished" +
                             ("; dependencies repaired" if r2.ok else
                              "; dependency repair needs an internet connection"),
                             commands=["dpkg --configure -a", "apt-get install -f -y"])

    def verify(self, ctx: RepairContext) -> RepairOutcome:
        # Re-read the package database rather than trusting the snapshot: this
        # is what makes the verification meaningful.
        from ..core.facts import read_dpkg_status
        from ..checks.software_errors import dpkg_problems
        bad = dpkg_problems(read_dpkg_status() or ctx.f.packages)
        state = f"packages needing attention: {', '.join(n for n, _ in bad) or 'none'}"
        return RepairOutcome(not bad, state, before=state, after=state)

    def rollback(self, ctx: RepairContext):
        """Not reversible: a package repair cannot be undone."""
        return RepairOutcome(False, "Package configuration cannot be un-done; re-install the "
                                    "affected packages if something is still wrong.")


for _repair in (XfceCompositingRepair(), KeyRepeatRepair(), KeyboardLayoutRepair(),
                EnableKeyboardRepair(), FixDpkgRepair()):
    register_repair(_repair)
