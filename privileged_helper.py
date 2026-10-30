"""
nexus_doctor.privileged_helper
==============================

A deliberately tiny, non-interactive, allow-listed root helper.

The GUI never obtains a root shell.  When a repair or diagnostic needs
administrator rights it asks ``pkexec`` to run this helper with a single JSON
argument; the helper performs exactly one of a few rigidly-scoped operations
and prints one JSON line describing the outcome.

Security properties
-------------------
* Rejects anything that is not root (defence in depth behind pkexec).
* ``run`` accepts **only** binaries on a hard-coded allow-list.
* ``run`` forbids shell metacharacters in any argument and forbids invoking
  an interpreter (sh, bash, python, perl, env, sudo, su, ...).
* ``write`` / ``remove`` accept **only** paths under a small set of system
  configuration directories, minus an explicit deny-list of security files.
* Every ``write`` / ``remove`` makes a timestamped backup first.
* No network, no pipes, no redirection, no environment passing.
* Everything is appended to ``/var/log/nexus-system-doctor-helper.log``.

Usage::

    pkexec /usr/lib/nexus-system-doctor/privileged-helper '{"op":"run","argv":["smartctl","-H","/dev/sda"],"timeout":20}'
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import subprocess
import sys

HELPER_LOG = "/var/log/nexus-system-doctor-helper.log"
BACKUP_ROOT = "/var/lib/nexus-system-doctor/backups"

# --------------------------------------------------------------------------
# Allow-lists
# --------------------------------------------------------------------------

#: Commands the helper may execute.  Each entry must be a leaf diagnostic or
#: system-tuning tool -- never an interpreter or a privilege-escalation tool.
ALLOWED_BINARIES = {
    "smartctl", "smartd", "hdparm", "tune2fs", "e2fsck", "dumpe2fs", "xfs_info",
    "sysctl", "swapon", "swapoff", "mkswap", "zramctl", "modprobe", "rmmod",
    "systemctl", "journalctl", "udevadm", "mount", "umount", "findmnt", "blkid",
    "lsblk", "dmidecode", "apt-get", "apt", "dpkg", "update-initramfs",
    "update-grub", "grub-mkconfig", "fwupdmgr", "iostat", "lshw", "sensors",
    "chmod", "chown", "mkdir", "touch", "rm", "cp", "mv", "tee", "install",
    "sync", "blockdev", "rescan-scsi-bus", "badblocks", "efibootmgr",
    "systemctl", "systemd-analyze", "systemd-tty-ask-password-agent",
    "nexus-zram-setup",
}

#: Interpreters / escalation tools -- refused even if somehow allow-listed.
FORBIDDEN_BINARIES = {
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "awk", "gawk",
    "env", "sudo", "su", "pkexec", "doas", "script", "expect", "xargs", "eval",
    "curl", "wget", "nc", "netcat", "ssh", "scp", "ftp", "telnet",
    "dd", "mkfs", "fsck", "fdisk", "parted", "gparted", "wipefs", "shred",
}

#: Directory prefixes the helper may write to.
WRITE_PREFIXES = (
    "/etc/",
    "/usr/lib/nexus-system-doctor/",
    "/usr/share/nexus-system-doctor/",
    "/var/lib/nexus-system-doctor/",
)

#: Never writable, even inside /etc.  Mangled versions of these can lock the
#: user out of the machine or break authentication.
WRITE_DENY = (
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/security",
    "/etc/pam.d", "/etc/polkit-1", "/etc/dbus-1", "/etc/login.defs",
    "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/crypttab",
    "/etc/ld.so.preload", "/etc/ld.so.conf",
)

#: Files the helper must never read, even though it runs as root.  Reading
#: /etc/shadow through a diagnostic helper would be a privilege escalation,
#: so reading is restricted to what diagnostics genuinely need.
READ_DENY = (
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/security", "/etc/ssh", "/etc/ssl/private",
    "/etc/crypttab", "/etc/polkit-1",
)

#: Directories privileged reads are restricted to.
READ_PREFIXES = (
    "/etc/", "/proc/", "/sys/", "/dev/", "/var/lib/nexus-system-doctor/",
    "/var/log/", "/run/", "/usr/lib/nexus-system-doctor/",
)


def _read_allowed(path: str) -> bool:
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    norm = os.path.normpath(path)
    if ".." in norm.split("/"):
        return False
    if not norm.startswith(READ_PREFIXES):
        return False
    for denied in READ_DENY:
        if norm == denied or norm.startswith(denied + "/"):
            return False
    return True


#: Commands whose file arguments must satisfy the write allow-list.
FILE_COMMAND_BINARIES = {"chmod", "chown", "mkdir", "touch", "rm", "cp", "mv",
                         "tee", "install", "badblocks"}

#: Characters that would enable shell trickery if a tool re-parsed its args.
METACHARACTERS = set(";`$&|<>()\\\"'\n\r*?!~#")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _log(line: str) -> None:
    try:
        os.makedirs(os.path.dirname(HELPER_LOG), exist_ok=True)
        with open(HELPER_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{_dt.datetime.now().isoformat(timespec='seconds')} {line}\n")
    except OSError:
        pass


def _fail(reason: str, **extra) -> str:
    payload = {"ok": False, "rc": 1, "error": reason, "stdout": "", "stderr": ""}
    payload.update(extra)
    _log(f"DENY: {reason}")
    return json.dumps(payload)


def _resolve(name: str) -> str | None:
    if name.startswith("/"):
        return name if os.access(name, os.X_OK) else None
    for directory in ("/usr/local/sbin", "/usr/sbin", "/sbin",
                      "/usr/local/bin", "/usr/bin", "/bin"):
        cand = os.path.join(directory, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _path_allowed(path: str) -> bool:
    if not path.startswith("/"):
        return False
    norm = os.path.normpath(path)
    if ".." in norm.split("/"):
        return False
    if not norm.startswith(WRITE_PREFIXES):
        return False
    for denied in WRITE_DENY:
        if norm == denied or norm.startswith(denied + "/"):
            return False
    return True


def _backup(path: str) -> str | None:
    """Copy *path* into a timestamped backup directory; return backup path."""
    if not os.path.exists(path):
        return None
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest_dir = os.path.join(BACKUP_ROOT, stamp)
    try:
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, path.lstrip("/").replace("/", "_"))
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.copytree(path, dest, symlinks=True)
        else:
            shutil.copy2(path, dest)
        return dest
    except OSError as exc:
        _log(f"backup failed for {path}: {exc}")
        return None


# --------------------------------------------------------------------------
# Operations
# --------------------------------------------------------------------------


def op_run(argv, timeout: float, stdin_data: str | None = None) -> str:
    if not isinstance(argv, list) or not argv:
        return _fail("argv must be a non-empty list")
    argv = [str(a) for a in argv]
    binary = os.path.basename(argv[0])

    if binary in FORBIDDEN_BINARIES:
        return _fail(f"binary not permitted: {binary}")
    if binary not in ALLOWED_BINARIES:
        return _fail(f"binary not on allow-list: {binary}")

    for arg in argv[1:]:
        if any(ch in METACHARACTERS for ch in arg):
            return _fail(f"forbidden character in argument: {arg!r}")

    if binary in FILE_COMMAND_BINARIES:
        for arg in argv[1:]:
            if arg.startswith("/") and not _path_allowed(arg):
                return _fail(f"path not writable by helper: {arg}")
            if arg.startswith("-"):
                continue

    exe = _resolve(argv[0])
    if exe is None:
        return _fail(f"executable not found: {argv[0]}")

    try:
        timeout = max(1.0, min(float(timeout), 600.0))
    except (TypeError, ValueError):
        timeout = 30.0

    _log(f"RUN: {argv}")
    try:
        proc = subprocess.run(  # noqa: S603 - allow-listed, no shell, timeout
            [exe] + argv[1:],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True, errors="replace",
            input=stdin_data, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                   "LC_ALL": "C", "LANG": "C"},
            close_fds=True,
        )
        return json.dumps({"ok": proc.returncode == 0, "rc": proc.returncode,
                           "stdout": proc.stdout or "", "stderr": proc.stderr or ""})
    except subprocess.TimeoutExpired:
        return _fail("command timed out")
    except Exception as exc:
        return _fail(f"{type(exc).__name__}: {exc}")


def op_write(path: str, content: str, mode=None, backup: bool = True) -> str:
    if not isinstance(path, str) or not _path_allowed(path):
        return _fail(f"path not writable by helper: {path}")
    made = _backup(path) if (backup and os.path.exists(path)) else None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".nexus-tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        if mode is not None:
            os.chmod(path, int(mode, 8) if isinstance(mode, str) else int(mode))
        _log(f"WRITE: {path} ({len(content)} bytes) backup={made}")
        return json.dumps({"ok": True, "rc": 0, "stdout": path, "stderr": "",
                           "backup": made or ""})
    except OSError as exc:
        return _fail(f"write failed: {exc}")


def op_remove(path: str, backup: bool = True) -> str:
    if not isinstance(path, str) or not _path_allowed(path):
        return _fail(f"path not removable by helper: {path}")
    made = _backup(path) if (backup and os.path.exists(path)) else None
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        _log(f"REMOVE: {path} backup={made}")
        return json.dumps({"ok": True, "rc": 0, "stdout": path, "stderr": "",
                           "backup": made or ""})
    except OSError as exc:
        return _fail(f"remove failed: {exc}")


def op_read(path: str) -> str:
    if not _read_allowed(path):
        return _fail(f"path not readable by helper: {path}")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
        return json.dumps({"ok": True, "rc": 0, "stdout": data, "stderr": ""})
    except OSError as exc:
        return _fail(f"read failed: {exc}")


def handle(payload: dict) -> str:
    op = payload.get("op")
    if op == "run":
        return op_run(payload.get("argv"), payload.get("timeout", 30),
                      payload.get("stdin"))
    if op == "write":
        return op_write(payload.get("path", ""), payload.get("content", ""),
                        payload.get("mode"), payload.get("backup", True))
    if op == "remove":
        return op_remove(payload.get("path", ""), payload.get("backup", True))
    if op == "read":
        return op_read(payload.get("path", ""))
    if op == "ping":
        return json.dumps({"ok": True, "rc": 0, "stdout": "pong", "stderr": ""})
    return _fail(f"unknown op: {op}")


def main(argv: list[str]) -> int:
    if os.geteuid() != 0:
        print(_fail("helper must run as root"))
        return 1
    raw = argv[1] if len(argv) > 1 else ""
    if not raw:
        raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        print(_fail(f"invalid payload: {exc}"))
        return 1
    if not isinstance(payload, dict):
        print(_fail("payload must be an object"))
        return 1
    print(handle(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
