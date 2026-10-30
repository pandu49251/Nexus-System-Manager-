"""
nexus_doctor.core.privileges
============================

Privilege handling.

Most diagnostics (``/proc``, ``/sys``, most of ``/etc``) are readable by an
ordinary user.  A handful genuinely need root: SMART queries, ``tune2fs``,
journal vacuuming, sysctl changes, swap setup, service management.

Three rules govern this module:

1.  **Never silently downgrade.**  If a command needs root and we cannot get
    it, the caller receives ``state="error"`` with an explanation.  The check
    then reports "incomplete evidence - rerun with administrator rights"
    instead of pretending the disk is healthy.
2.  **Minimum surface.**  Root commands go through a tiny helper with a
    hard-coded binary allow-list and an ``/etc``-only write allow-list
    (see :mod:`nexus_doctor.privileged_helper`).  The GUI never gets a root
    shell.
3.  **GUI actions run as the user.**  ``xset``, ``xfconf-query`` and friends
    must run inside the user's X session.  When the app is elevated we
    re-drop to the invoking user with the session environment recovered from
    ``/proc/<pid>/environ`` (``DISPLAY``, ``XAUTHORITY``, ``DBUS_SESSION_BUS_ADDRESS``).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Sequence

from .executil import Result, run

log = logging.getLogger("nexus.priv")

HELPER_PATHS = (
    "/usr/lib/nexus-system-doctor/privileged-helper",
    "/usr/libexec/nexus-system-doctor/privileged-helper",
    "/opt/nexus-system-doctor/privileged-helper",
)

_X_ENV_CACHE: Optional[Dict[str, str]] = None


def euid() -> int:
    try:
        return os.geteuid()
    except AttributeError:  # pragma: no cover - non-POSIX
        return -1


def is_root() -> bool:
    # Test hook: the harness replays a fixture machine with NEXUS_TEST_ROOT=1
    # so the privileged repair path can be exercised without pkexec. It is
    # ignored unless NEXUS_FIXTURES is also set, so a real scan is unaffected.
    if os.environ.get("NEXUS_TEST_ROOT") == "1" and os.environ.get("NEXUS_FIXTURES"):
        return True
    return euid() == 0


def current_user() -> str:
    for var in ("SUDO_USER", "PKEXEC_UID", "USER", "LOGNAME"):
        val = os.environ.get(var)
        if val and val != "root":
            return val
    if is_root():
        sudo = os.environ.get("SUDO_USER")
        if sudo:
            return sudo
    return os.environ.get("USER", "unknown")


def _helper_path() -> Optional[str]:
    """Locate the privileged helper installed alongside the application."""
    for cand in HELPER_PATHS:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    # Development / portable layout: helper next to the package.
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cand = os.path.join(os.path.dirname(here), "share", "privileged-helper")
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    return None


def _pkexec() -> Optional[str]:
    p = shutil.which("pkexec")
    if p and os.access(p, os.X_OK):
        return p
    return "/usr/bin/pkexec" if os.path.isfile("/usr/bin/pkexec") else None


def sudo_noninteractive() -> bool:
    """True if ``sudo -n`` can run without prompting right now."""
    if is_root():
        return True
    sudo = shutil.which("sudo")
    if not sudo:
        return False
    try:
        p = subprocess.run([sudo, "-n", "true"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=8)
        return p.returncode == 0
    except Exception:
        return False


def elevation_method() -> str:
    """Which elevation path will actually be used ('root', 'pkexec', 'sudo', 'none')."""
    if is_root():
        return "root"
    if _pkexec():
        return "pkexec"
    if sudo_noninteractive():
        return "sudo"
    return "none"


def can_elevate() -> bool:
    return elevation_method() != "none"


def _helper_payload(argv: Sequence[str], timeout: float, stdin_data: Optional[str]) -> str:
    return json.dumps({"op": "run", "argv": list(argv), "timeout": timeout,
                       "stdin": stdin_data})


def _helper_call(payload: Dict[str, object], timeout: float = 60.0) -> Dict[str, object]:
    """Send one operation to the privileged helper and return its JSON reply."""
    helper = _helper_path()
    pk = _pkexec()
    if not helper:
        return {"ok": False, "rc": 1, "error": "privileged helper is not installed"}
    argv = [pk] + ([helper] if pk else []) + [json.dumps(payload)]
    try:
        p = subprocess.run(  # noqa: S603 - argv list, no shell
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True, errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": 1, "error": "helper timed out"}
    except Exception as exc:
        return {"ok": False, "rc": 1, "error": f"{type(exc).__name__}: {exc}"}
    for line in reversed((p.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return {"ok": False, "rc": p.returncode,
            "error": (p.stderr or "helper produced no JSON").strip()[:200]}


def write_as_root(path: str, content: str, mode: Optional[int] = None,
                  backup: bool = True) -> Dict[str, object]:
    """Write a system configuration file through the allow-listed helper."""
    if is_root():
        from . import executil
        executil.write_text(path, content, mode=mode)
        return {"ok": True, "rc": 0, "stdout": path, "stderr": "", "backup": ""}
    return _helper_call({"op": "write", "path": path, "content": content,
                         "mode": oct(mode) if mode else None, "backup": backup})


def remove_as_root(path: str, backup: bool = True) -> Dict[str, object]:
    """Delete a system configuration file through the allow-listed helper."""
    if is_root():
        from . import executil
        executil.remove(path)
        return {"ok": True, "rc": 0, "stdout": path, "stderr": "", "backup": ""}
    return _helper_call({"op": "remove", "path": path, "backup": backup})


def run_as_root(argv: Sequence[str], timeout: float = 30.0,
                stdin_data: Optional[str] = None) -> Result:
    """Execute *argv* with administrator rights.

    Strategy, in order:
      * already root            -> run directly
      * pkexec + helper present -> run through the allow-listed helper
        (pkexec shows the standard graphical password prompt on Mint Xfce)
      * ``sudo -n`` possible    -> run via sudo without prompting
      * otherwise               -> honest failure
    """
    argv = [str(a) for a in argv]
    started = time.monotonic()

    if is_root():
        return run(argv, timeout=timeout, stdin_data=stdin_data, quiet=False)

    helper = _helper_path()
    pk = _pkexec()
    if helper and pk:
        payload = _helper_payload(argv, timeout, stdin_data)
        try:
            p = subprocess.run(  # noqa: S603
                [pk, helper, payload],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout + 30, text=True, errors="replace",
            )
            dur = int((time.monotonic() - started) * 1000)
            out, err = (p.stdout or "").strip(), (p.stderr or "").strip()
            if p.returncode != 0:
                return Result(argv=argv, rc=p.returncode, out=out, err=err,
                              duration_ms=dur, state="error", as_root=True,
                              detail="privileged helper failed (authentication cancelled?)")
            # Helper speaks JSON on the last line.
            parsed: Optional[Dict[str, object]] = None
            for line in reversed(out.splitlines()):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        parsed = json.loads(line)
                        break
                    except ValueError:
                        continue
            if parsed is None:
                return Result(argv=argv, rc=0, out=out, err=err, duration_ms=dur,
                              state="ok", as_root=True)
            return Result(
                argv=argv,
                rc=int(parsed.get("rc", 0)),
                out=str(parsed.get("stdout", "")),
                err=str(parsed.get("stderr", "")) or str(parsed.get("error", "")),
                duration_ms=dur,
                state="ok" if int(parsed.get("rc", 0)) == 0 else "error",
                as_root=True,
                detail=str(parsed.get("error", "")),
            )
        except subprocess.TimeoutExpired:
            return Result(argv=argv, state="timeout", as_root=True,
                          duration_ms=int(timeout * 1000),
                          detail="privileged helper timed out")
        except Exception as exc:
            return Result(argv=argv, state="exception", as_root=True,
                          detail=f"{type(exc).__name__}: {exc}")

    if sudo_noninteractive():
        return run(["sudo", "-n", "--"] + argv, timeout=timeout, stdin_data=stdin_data)

    return Result(argv=argv, state="error", as_root=True,
                  detail="administrator rights unavailable "
                         "(no pkexec, no passwordless sudo)")


# --------------------------------------------------------------------------
# Dropping back to the user (for X11 / Xfce settings)
# --------------------------------------------------------------------------

_X_KEYS = ("DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS",
           "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE", "WAYLAND_DISPLAY", "HOME", "USER")


def probe_x_env() -> Dict[str, str]:
    """Recover the graphical session environment.

    When the app runs as root the session variables are absent, so Xfce
    settings and ``xset`` would fail.  We read them from the environment of
    running user processes (only possible as root - which is exactly when we
    need it).  Falls back to the current environment.
    """
    global _X_ENV_CACHE
    if _X_ENV_CACHE is not None:
        return _X_ENV_CACHE
    env: Dict[str, str] = {}
    if is_root():
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            pids = []
        for pid in pids:
            try:
                with open(f"/proc/{pid}/environ", "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if b"DISPLAY=" not in raw:
                continue
            candidate: Dict[str, str] = {}
            for chunk in raw.split(b"\0"):
                if b"=" not in chunk:
                    continue
                k, _, v = chunk.partition(b"=")
                key = k.decode("utf-8", "replace")
                if key in _X_KEYS:
                    candidate[key] = v.decode("utf-8", "replace")
            if candidate.get("DISPLAY") and candidate.get("DBUS_SESSION_BUS_ADDRESS"):
                env = candidate
                break
    if not env:
        env = {k: v for k, v in os.environ.items() if k in _X_KEYS}
    _X_ENV_CACHE = env
    return env


def has_gui_session() -> bool:
    """True if we can plausibly talk to the user's graphical session."""
    env = probe_x_env()
    if not env.get("DISPLAY"):
        return False
    if env.get("XAUTHORITY"):
        return True
    user = env.get("USER") or current_user()
    return os.path.exists(f"/home/{user}/.Xauthority")


def run_as_user(argv: Sequence[str], timeout: float = 15.0) -> Result:
    """Run *argv* inside the user's session (used for xset / xfconf-query)."""
    argv = [str(a) for a in argv]
    env = probe_x_env()
    simulated = (os.environ.get("NEXUS_TEST_ROOT") == "1"
                 and os.environ.get("NEXUS_FIXTURES"))
    if not is_root() or simulated:
        merged = dict(os.environ)
        merged.update({k: v for k, v in env.items() if v})
        return run(argv, timeout=timeout, env=merged)
    user = current_user()
    if not user or user == "root":
        return run(argv, timeout=timeout, env={k: v for k, v in env.items() if v})
    runuser = shutil.which("runuser") or "/sbin/runuser"
    if not os.path.exists(runuser):
        return Result(argv=argv, state="missing", detail="runuser not available")
    cmd = [runuser, "-u", user, "--"] + argv
    merged = {"DISPLAY": env.get("DISPLAY", ":0"),
              "XAUTHORITY": env.get("XAUTHORITY", f"/home/{user}/.Xauthority"),
              "DBUS_SESSION_BUS_ADDRESS": env.get("DBUS_SESSION_BUS_ADDRESS", ""),
              "XDG_RUNTIME_DIR": env.get("XDG_RUNTIME_DIR", f"/run/user/{_uid_of(user)}"),
              "HOME": env.get("HOME", f"/home/{user}")}
    merged = {k: v for k, v in merged.items() if v}
    return run(cmd, timeout=timeout, env=merged)


def _uid_of(user: str) -> int:
    import pwd
    try:
        return pwd.getpwnam(user).pw_uid
    except Exception:
        return 1000


def user_home() -> str:
    if not is_root():
        return os.path.expanduser("~")
    env = probe_x_env()
    return env.get("HOME") or f"/home/{current_user()}"
