"""
nexus_doctor.core.executil
==========================

The single point of contact between Nexus System Doctor and the operating
system.  Every diagnostic check and every repair MUST go through this module.

Guarantees enforced here (see tests/test_purity.py, which fails the build if a
check or repair module bypasses this module):

1.  **No shell.**  Commands are always passed as an argv list; ``shell=True``
    is never used, so a filename containing ``; rm -rf /`` can never be
    executed as code.
2.  **Every command has a timeout.**  A wedged disk or a stuck USB probe can
    never hang the application.  Timeouts are reported honestly as failures.
3.  **Full audit trail.**  Every command (argv, exit status, wall time) is
    emitted to the application log, so every diagnosis can be traced back to
    the exact command that produced the evidence.
4.  **Missing tools are normal.**  Linux Mint Xfce minimal installs lack
    smartctl, lm-sensors, etc.  A missing tool yields ``state="missing"`` and a
    check degrades gracefully instead of inventing data.
5.  **Redirectable.**  ``NEXUS_SYSROOT`` redirects all filesystem access and
    ``NEXUS_FIXTURES`` redirects all commands, which makes the entire
    diagnostic engine testable offline against a synthetic machine.
6.  **Write protection.**  When ``NEXUS_SANDBOX`` is set, any write outside
    that directory raises ``SandboxViolation``.  The test-suite relies on this
    to prove that a "scan" is genuinely read-only.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

log = logging.getLogger("nexus.exec")

# --------------------------------------------------------------------------
# Environment-controlled redirection (test harness)
# --------------------------------------------------------------------------

#: Prefix for every filesystem path (used to point the app at a fake machine).
SYSROOT: str = os.environ.get("NEXUS_SYSROOT", "")
#: Directory containing a ``commands.json`` fixture file.
FIXTURES: str = os.environ.get("NEXUS_FIXTURES", "")
#: When set, writes are only permitted inside this directory.
SANDBOX: str = os.environ.get("NEXUS_SANDBOX", "")

_FIXTURE_CACHE: Optional[List[Dict[str, Any]]] = None
#: Tools the fixture machine pretends to have installed.
_FIXTURE_TOOLS: Optional[set] = None
#: 0 = pre-repair state, 1 = post-repair state.  Fixtures may declare
#: {"before": ..., "after": ...} so a verification step sees the new state.
_PHASE = 0


def set_phase(phase: int) -> None:
    """Switch the fixture machine between its pre-repair and post-repair state."""
    global _PHASE
    _PHASE = 1 if phase else 0


def get_phase() -> int:
    return _PHASE


def _phase_value(value):
    """Resolve a fixture value that may be a {before, after} mapping.

    Only a mapping that actually declares "before" or "after" is treated as a
    phase selector; any other dict is data (such as the statvfs table) and is
    returned untouched.
    """
    if isinstance(value, dict) and ("before" in value or "after" in value):
        return value.get("after" if _PHASE else "before", value.get("before"))
    return value


#: Files whose contents change on every read, so time-based measurements
#: (iowait sampling, CPU usage deltas) can be tested deterministically.
_TICKERS: Dict[str, List[str]] = {}
#: Fixture-provided uname output.
_FIXTURE_UNAME: Dict[str, str] = {}
_TICK_COUNT: Dict[str, int] = {}

# Directories that hold administrator-only binaries.  smartctl, hdparm,
# tune2fs and friends live in /usr/sbin, which is NOT in a normal user's PATH
# (verified on the reference system).  Without this, SMART data would silently
# "not be available" -- a false negative, which is worse than an error.
_SBIN_DIRS = ("/usr/local/sbin", "/usr/sbin", "/sbin")


class SandboxViolation(RuntimeError):
    """Raised when code attempts to write outside the permitted sandbox."""


# --------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------


def syspath(path: str) -> str:
    """Resolve an absolute system path through the test sysroot."""
    if not SYSROOT or not path.startswith("/"):
        return path
    return os.path.join(SYSROOT, path.lstrip("/"))


def exists(path: str) -> bool:
    try:
        return os.path.exists(syspath(path))
    except OSError:
        return False


def isfile(path: str) -> bool:
    try:
        return os.path.isfile(syspath(path))
    except OSError:
        return False


def isdir(path: str) -> bool:
    try:
        return os.path.isdir(syspath(path))
    except OSError:
        return False


def _ensure_fixtures() -> None:
    """Load the fixture tables on first use (they are consulted by readers too)."""
    if FIXTURES and _FIXTURE_CACHE is None:
        _fixtures()


def read_text(path: str, default: Optional[str] = None, errors: str = "replace") -> Optional[str]:
    """Read a whole text file. Returns *default* on any error."""
    if FIXTURES:
        _ensure_fixtures()
    if path in _TICKERS:
        variants = _phase_value(_TICKERS[path])
        if isinstance(variants, str):     # {before, after} form: already resolved
            return variants
        variants = variants or []
        idx = _TICK_COUNT.get(path, 0)
        _TICK_COUNT[path] = idx + 1
        return variants[idx % len(variants)]
    try:
        with open(syspath(path), "r", encoding="utf-8", errors=errors) as fh:
            return fh.read()
    except (OSError, ValueError):
        return default


def write_bytes(path: str, data: bytes, sync: bool = False,
                mode: Optional[int] = None) -> bool:
    """Write binary data, optionally flushing it to the physical device."""
    _check_write_allowed(path)
    real = syspath(path)
    try:
        os.makedirs(os.path.dirname(real) or ".", exist_ok=True)
        with open(real, "wb") as fh:
            fh.write(data)
            fh.flush()
            if sync:
                os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(real, mode)
        return True
    except OSError as exc:
        log.warning("failed to write %s: %s", path, exc)
        return False


def read_at(path: str, offsets: Sequence[int], block: int = 4096) -> int:
    """Read *block* bytes at each offset; returns the number of bytes read.

    Used by the disk benchmark so that it never opens a file itself.
    """
    total = 0
    try:
        with open(syspath(path), "rb", buffering=0) as fh:
            for off in offsets:
                fh.seek(off)
                total += len(fh.read(block))
    except OSError:
        return total
    return total


def file_size(path: str) -> Optional[int]:
    try:
        return os.path.getsize(syspath(path))
    except OSError:
        return None


def read_bytes(path: str, length: int = -1) -> Optional[bytes]:
    try:
        with open(syspath(path), "rb") as fh:
            return fh.read() if length < 0 else fh.read(length)
    except OSError:
        return None


def read_lines(path: str, default: Optional[List[str]] = None) -> Optional[List[str]]:
    txt = read_text(path)
    if txt is None:
        return default
    return txt.splitlines()


def listdir(path: str) -> List[str]:
    try:
        return sorted(os.listdir(syspath(path)))
    except OSError:
        return []


def readlink(path: str) -> Optional[str]:
    try:
        return os.readlink(syspath(path))
    except OSError:
        return None


def _check_write_allowed(path: str) -> None:
    """Refuse to write anywhere the sandbox does not cover.

    When a sysroot is configured (testing against a fake machine) absolute
    paths are interpreted relative to it, exactly as :func:`syspath` does, so
    ``/etc/fstab`` means "the fixture's /etc/fstab".  Without a sysroot the
    path is a real path on this machine and is checked literally - otherwise
    the sandbox would silently permit writes to the real /etc.
    """
    if not SANDBOX:
        return
    if path.startswith("/") and SYSROOT:
        target = os.path.realpath(os.path.join(SANDBOX, path.lstrip("/")))
    else:
        target = os.path.realpath(path)
    root = os.path.realpath(SANDBOX)
    if not (target == root or target.startswith(root + os.sep)):
        raise SandboxViolation(f"refusing to write outside sandbox: {path}")


def write_text(path: str, content: str, mode: Optional[int] = None, atomic: bool = True) -> bool:
    """Write a text file, optionally atomically (write temp + rename)."""
    _check_write_allowed(path)
    real = syspath(path)
    try:
        os.makedirs(os.path.dirname(real), exist_ok=True)
        if atomic:
            tmp = real + ".nexus-tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, real)
        else:
            with open(real, "w", encoding="utf-8") as fh:
                fh.write(content)
        if mode is not None:
            os.chmod(real, mode)
        log.info("wrote file %s (%d bytes)", path, len(content))
        return True
    except OSError as exc:
        log.warning("failed to write %s: %s", path, exc)
        return False


def remove(path: str) -> bool:
    _check_write_allowed(path)
    real = syspath(path)
    try:
        if os.path.isdir(real) and not os.path.islink(real):
            shutil.rmtree(real)
        else:
            os.remove(real)
        log.info("removed %s", path)
        return True
    except OSError as exc:
        log.warning("failed to remove %s: %s", path, exc)
        return False


class _FakeStatvfs:
    """Stand-in for os.statvfs results, used when replaying a fixture machine."""

    def __init__(self, total: int, avail: int, inodes_total: int = 0, inodes_free: int = 0,
                 frsize: int = 4096):
        self.f_frsize = frsize
        self.f_blocks = max(1, total // frsize)
        # Blocks free vs. available: on ext4 a share is reserved for root, so
        # f_bfree is slightly larger than f_bavail.  Without that distinction
        # "used" would be computed against the wrong base and report 100%.
        self.f_bavail = max(0, avail // frsize)
        self.f_bfree = max(self.f_bavail, int(self.f_bavail * 1.05))
        self.f_files = inodes_total
        self.f_ffree = inodes_free


#: Fixture-provided filesystem usage: mountpoint -> {total, avail, ...}
_STATVFS_FIXTURES: Dict[str, Dict[str, int]] = {}
#: Fixture-provided directory sizes (avoids creating hundreds of MB of files
#: just to test a "disk is full" code path): path -> bytes.
_DIR_SIZE_FIXTURES: Dict[str, int] = {}


def statvfs(path: str):
    """os.statvfs, redirected to fixture data when replaying a machine."""
    if FIXTURES:
        _ensure_fixtures()
        if path in _STATVFS_FIXTURES:
            return _FakeStatvfs(**_phase_value(_STATVFS_FIXTURES[path]))
    import os as _os
    return _os.statvfs(syspath(path))


def dir_size(path: str, max_entries: int = 20000) -> int:
    """Total size of a directory tree, bounded so it can never run away."""
    if FIXTURES:
        _ensure_fixtures()
        if path in _DIR_SIZE_FIXTURES:
            value = _phase_value(_DIR_SIZE_FIXTURES[path])
            if isinstance(value, list):      # sequence of successive answers
                idx = _TICK_COUNT.get("dir:" + path, 0)
                _TICK_COUNT["dir:" + path] = idx + 1
                return int(value[min(idx, len(value) - 1)])
            return int(value)
    total = 0
    seen = 0
    root = syspath(path)
    for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        for name in filenames:
            seen += 1
            if seen > max_entries:
                return total
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                pass
    return total


# --------------------------------------------------------------------------
# Tool resolution
# --------------------------------------------------------------------------

_TOOL_CACHE: Dict[str, Optional[str]] = {}


def find_tool(name: str) -> Optional[str]:
    """Locate an executable, including the sbin directories."""
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]
    if FIXTURES:
        if _FIXTURE_TOOLS is None:
            _fixtures()
        tools = _FIXTURE_TOOLS or set()
        found = name if name in tools else None
        _TOOL_CACHE[name] = found
        return found
    found = shutil.which(name)
    if not found and not name.startswith("/"):
        for d in _SBIN_DIRS:
            cand = os.path.join(d, name)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                found = cand
                break
    _TOOL_CACHE[name] = found
    return found


def have_tool(name: str) -> bool:
    return find_tool(name) is not None


def kernel_version() -> str:
    """Running kernel release (fakeable, because fixtures replay one machine)."""
    if FIXTURES:
        _fixtures()
        return str(_FIXTURE_UNAME.get("release") or os.uname().release)
    return os.uname().release


# --------------------------------------------------------------------------
# Command execution
# --------------------------------------------------------------------------


@dataclass
class Result:
    """Outcome of a command.  Never raises: inspect ``state``."""

    argv: List[str]
    rc: int = -1
    out: str = ""
    err: str = ""
    duration_ms: int = 0
    state: str = "error"  # ok | error | missing | timeout | fixture | exception
    detail: str = ""
    as_root: bool = False

    @property
    def ok(self) -> bool:
        return self.state == "ok" and self.rc == 0

    @property
    def lines(self) -> List[str]:
        return self.out.splitlines()

    @property
    def first(self) -> str:
        for line in self.lines:
            if line.strip():
                return line.strip()
        return ""

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Result {self.state} rc={self.rc} {' '.join(self.argv)!r}>"


def _fixtures() -> List[Dict[str, Any]]:
    """Load and cache the command fixture table (test mode only)."""
    global _FIXTURE_CACHE
    if _FIXTURE_CACHE is not None:
        return _FIXTURE_CACHE
    global _FIXTURE_TOOLS, _TICKERS, _STATVFS_FIXTURES
    _FIXTURE_CACHE = []
    if not FIXTURES:
        return _FIXTURE_CACHE
    path = os.path.join(FIXTURES, "commands.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            _FIXTURE_CACHE = data
            _FIXTURE_TOOLS = None
        else:
            _FIXTURE_CACHE = data.get("commands", [])
            _FIXTURE_TOOLS = set(data.get("tools", []) or [])
            _TICKERS = {k: v for k, v in (data.get("tickers") or {}).items()
                        if isinstance(v, (list, dict))}
            _STATVFS_FIXTURES.update(
                {k: v for k, v in (data.get("statvfs") or {}).items()
                 if isinstance(v, dict)})
            for _k, _v in (data.get("dir_sizes") or {}).items():
                # A list answers successive calls in order; a {before, after}
                # mapping answers according to the current repair phase.
                if isinstance(_v, list):
                    _DIR_SIZE_FIXTURES[_k] = [int(x) for x in _v]
                elif isinstance(_v, dict):
                    _DIR_SIZE_FIXTURES[_k] = {kk: int(vv) for kk, vv in _v.items()}
                else:
                    _DIR_SIZE_FIXTURES[_k] = int(_v)
            if isinstance(data.get("uname"), dict):
                _FIXTURE_UNAME.update(data["uname"])
    except (OSError, ValueError) as exc:
        log.error("could not load fixtures from %s: %s", path, exc)
    return _FIXTURE_CACHE


_RESPONSE_IDX: Dict[int, int] = {}


def _next_response(entry: Dict[str, Any]) -> Dict[str, Any]:
    if "before" in entry or "after" in entry:
        merged = dict(entry)
        step = entry.get("after" if _PHASE else "before", {})
        merged.update(step if isinstance(step, dict) else {"out": step})
        return merged
    return _next_response_seq(entry)


def _next_response_seq(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return *entry*, or its Nth canned response if it declares a sequence.

    This is what makes "verify, apply, verify again" testable: a command such
    as ``xset q`` can answer with the old value twice and the new value after
    the repair has run.
    """
    responses = entry.get("responses")
    if not isinstance(responses, list) or not responses:
        return entry
    key = id(entry)
    idx = _RESPONSE_IDX.get(key, 0)
    _RESPONSE_IDX[key] = idx + 1
    step = responses[min(idx, len(responses) - 1)]
    merged = dict(entry)
    merged.update(step if isinstance(step, dict) else {"out": step})
    return merged


def _match_fixture(argv: Sequence[str]) -> Optional[Dict[str, Any]]:
    """Best match of argv against the fixture table.

    Scored on (number of matched tokens, has a 'contains' guard), so a
    specific rule such as ``["xfconf-query"], contains="use_compositing"``
    beats a generic ``["xfconf-query"]`` rule.
    """
    best: Optional[Dict[str, Any]] = None
    best_score = (-1, -1)
    for entry in _fixtures():
        match = entry.get("match") or []
        if not isinstance(match, list) or not match:
            continue
        if len(argv) < len(match):
            continue
        if list(argv[: len(match)]) != [str(m) for m in match]:
            continue
        guard = entry.get("contains")
        if guard and guard not in " ".join(argv):
            continue
        score = (1 if guard else 0, len(match))
        if score > best_score:
            best = entry
            best_score = score
    return best


def run(
    argv: Sequence[str],
    timeout: float = 15.0,
    root: bool = False,
    env: Optional[Dict[str, str]] = None,
    stdin_data: Optional[str] = None,
    cwd: Optional[str] = None,
    quiet: bool = False,
) -> Result:
    """Run a command safely.

    *argv* must be a list (never a string) -- construction with ``shell=True``
    is impossible by design.  *root* requests privilege elevation via the
    privilege layer; if elevation is impossible the result is ``state="error"``
    with an explanatory ``detail``, never a silent unprivileged attempt.
    """
    argv = [str(a) for a in argv]
    started = time.monotonic()

    if not argv:
        return Result(argv=argv, state="error", detail="empty command")

    # ---- test redirection -------------------------------------------------
    if FIXTURES:
        # Normalise argv[0]: in fixture mode the real absolute path is
        # irrelevant, and matching on the basename keeps fixtures portable.
        argv = [os.path.basename(argv[0])] + list(argv[1:])
        fx = _match_fixture(argv)
        if fx is not None:
            fx = _next_response(fx)
            dur = int((time.monotonic() - started) * 1000)
            res = Result(
                argv=argv,
                rc=int(fx.get("rc", 0)),
                out=fx.get("out", "") or "",
                err=fx.get("err", "") or "",
                duration_ms=dur,
                state="ok" if int(fx.get("rc", 0)) == 0 else "error",
                as_root=root,
            )
            log.debug("fixture %s -> rc=%s", argv, res.rc)
            return res
        # Not in the fixture table: an honest "no data" rather than a guess.
        log.debug("no fixture for %s", argv)
        return Result(argv=argv, state="missing", detail="no fixture entry", as_root=root)

    # ---- real execution ---------------------------------------------------
    if root:
        from . import privileges  # local import: privileges imports executil

        return privileges.run_as_root(argv, timeout=timeout, stdin_data=stdin_data)

    exe = argv[0]
    if not exe.startswith("/"):
        resolved = find_tool(exe)
        if resolved is None:
            return Result(argv=argv, state="missing", detail=f"command not found: {exe}")
        exe = resolved
    final = [exe] + list(argv[1:])

    run_env = None
    if env:
        run_env = dict(os.environ)
        run_env.update(env)

    try:
        proc = subprocess.run(  # noqa: S603 - argv list, no shell, timeout set
            final,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=run_env,
            cwd=cwd,
            input=stdin_data.encode() if stdin_data is not None else None,
            text=True,
            errors="replace",
            close_fds=True,
        )
        dur = int((time.monotonic() - started) * 1000)
        res = Result(
            argv=argv,
            rc=proc.returncode,
            out=proc.stdout or "",
            err=proc.stderr or "",
            duration_ms=dur,
            state="ok" if proc.returncode == 0 else "error",
            as_root=False,
        )
    except subprocess.TimeoutExpired:
        res = Result(argv=argv, state="timeout", duration_ms=int(timeout * 1000),
                     detail=f"timed out after {timeout}s")
        dur = res.duration_ms
    except FileNotFoundError:
        res = Result(argv=argv, state="missing", detail=f"command not found: {exe}")
    except PermissionError:
        res = Result(argv=argv, state="error", detail="permission denied")
    except Exception as exc:  # pragma: no cover - defensive
        res = Result(argv=argv, state="exception", detail=f"{type(exc).__name__}: {exc}")

    if not quiet:
        log.debug("exec %s -> %s rc=%s %dms", " ".join(argv), res.state, res.rc, res.duration_ms)
    return res


def run_ok(argv: Sequence[str], **kw) -> Optional[str]:
    """Return stdout on success, ``None`` otherwise.  Convenience for probes."""
    r = run(argv, **kw)
    return r.out if r.ok else None


def run_lines(argv: Sequence[str], **kw) -> List[str]:
    r = run(argv, **kw)
    return r.lines if r.ok else []


__all__ = [
    "Result", "SandboxViolation", "run", "run_ok", "run_lines",
    "read_text", "read_lines", "read_bytes", "write_text", "remove", "listdir",
    "exists", "isfile", "isdir", "readlink", "dir_size", "syspath",
    "find_tool", "have_tool", "kernel_version", "SYSROOT", "SANDBOX",
    "FIXTURES",
]
