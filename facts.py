"""
nexus_doctor.core.facts
=======================

One-pass collection of the machine's ground truth.

Every check needs *some* of the same data (CPU model, memory totals, block
devices, installed packages, kernel command line).  Reading them once here
keeps the scan cheap -- important on a 1 TB mechanical HDD where every
unnecessary 10 MB read costs real time -- and guarantees that all checks
reason about the *same* snapshot of the machine.

Nothing here writes, and nothing here can fail hard: every accessor returns a
safe default.  A missing file is recorded as a missing fact, never as a
diagnosis.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from . import executil as ex
from .models import MachineProfile


def _read_kv(path: str, sep: str = "=") -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in ex.read_lines(path, []):
        if sep in line:
            k, _, v = line.partition(sep)
            out[k.strip()] = v.strip().strip('"')
    return out


@dataclass
class Facts:
    """A read-only snapshot of everything the scan needs."""

    os_release: Dict[str, str] = field(default_factory=dict)
    distro: str = ""
    desktop: str = ""
    desktop_version: str = ""
    kernel: str = ""
    cmdline: str = ""
    cmdline_args: List[str] = field(default_factory=list)
    uptime_s: float = 0.0

    cpu_model: str = ""
    cpu_vendor: str = ""
    cpu_cores: int = 0
    cpu_threads: int = 0
    cpu_family: str = ""
    cpu_model_id: str = ""
    cpu_flags: Set[str] = field(default_factory=set)
    cpu_max_mhz: float = 0.0
    cpu_governor: str = ""
    cpu_driver: str = ""
    cpu_microcode: str = ""

    meminfo: Dict[str, int] = field(default_factory=dict)
    loadavg: List[float] = field(default_factory=list)
    stat_iowait: int = 0

    machine: MachineProfile = field(default_factory=MachineProfile)

    block_devices: List[Dict[str, Any]] = field(default_factory=list)
    mounts: List[Dict[str, str]] = field(default_factory=list)

    packages: Dict[str, str] = field(default_factory=dict)   # name -> status ("ii", "rc", ...)
    modules: Set[str] = field(default_factory=set)

    hostname: str = ""
    user: str = ""

    # -- convenience -------------------------------------------------------
    def mem_total_mb(self) -> int:
        return self.meminfo.get("MemTotal", 0) // 1024

    def mem_available_mb(self) -> int:
        return self.meminfo.get("MemAvailable", 0) // 1024

    def has_package(self, name: str) -> bool:
        return self.packages.get(name, "").startswith("ii")

    def package_status(self, name: str) -> str:
        return self.packages.get(name, "")

    def has_module(self, name: str) -> bool:
        return name in self.modules

    def root_device(self) -> str:
        """Kernel device name backing / (e.g. 'sda'), derived from mounts."""
        for m in self.mounts:
            if m.get("mountpoint") == "/":
                src = m.get("device", "")
                if src.startswith("/dev/"):
                    name = re.sub(r"\d+$", "", src.replace("/dev/", ""))
                    return name if self._is_block_device(name) else \
                        self._resolve_pseudo_device(name, src)
        return ""

    @staticmethod
    def _is_block_device(name: str) -> bool:
        return bool(name) and ex.isdir(f"/sys/block/{name}")

    @staticmethod
    def _resolve_pseudo_device(name: str, src: str) -> str:
        """Map /dev/root (and similar) onto the real block device.

        Containers, some initramfs setups and a few cloud images mount / from
        ``/dev/root``, which is not a node in /sys/block.  Reporting the disk
        as "root" would leave every storage check without a device, so fall
        back to the major:minor pair in /proc/self/mountinfo and match it
        against /sys/block/*/dev.
        """
        if name not in ("root", "overlay", "", "mapper"):
            return name
        link = ex.readlink(src)
        if link and link.startswith("/dev/"):
            resolved = re.sub(r"\d+$", "", link.replace("/dev/", ""))
            if Facts._is_block_device(resolved):
                return resolved
        info = ex.read_text("/proc/self/mountinfo") or ""
        for line in info.splitlines():
            bits = line.split()
            if len(bits) >= 5 and bits[4] == "/" and ":" in bits[2]:
                wanted = bits[2]
                break
        else:
            return name
        for entry in ex.listdir("/sys/block"):
            dev = (ex.read_text(f"/sys/block/{entry}/dev") or "").strip()
            if dev and dev == wanted:
                return entry
        return name

    def root_mount(self) -> Dict[str, str]:
        for m in self.mounts:
            if m.get("mountpoint") == "/":
                return m
        return {}

    def physical_disks(self) -> List[Dict[str, Any]]:
        return [d for d in self.block_devices if d.get("type") == "disk"
                and not d["name"].startswith(("loop", "ram", "zram", "sr", "fd"))]

    def is_hdd(self, name: str) -> bool:
        for d in self.block_devices:
            if d["name"] == name:
                return bool(d.get("rotational"))
        return False

    def is_laptop(self) -> bool:
        if self.machine.chassis.lower() in ("laptop", "notebook", "convertible",
                                            "sub-notebook", "hand held"):
            return True
        return ex.isdir("/sys/class/power_supply") and any(
            n.startswith("BAT") for n in ex.listdir("/sys/class/power_supply"))

    def desktop_is_xfce(self) -> bool:
        return "xfce" in self.desktop.lower()

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        d["machine"] = self.machine.__dict__
        d["cpu_flags"] = sorted(self.cpu_flags)
        d["modules"] = sorted(self.modules)
        return d


# --------------------------------------------------------------------------
# Individual collectors
# --------------------------------------------------------------------------


def _collect_os(f: Facts) -> None:
    f.os_release = _read_kv("/etc/os-release")
    name = f.os_release.get("PRETTY_NAME") or f.os_release.get("NAME", "")
    f.distro = name.strip()
    edition = (f.os_release.get("VARIANT") or f.os_release.get("EDITION") or "").strip()
    f.kernel = ex.kernel_version()
    f.cmdline = (ex.read_text("/proc/cmdline") or "").strip()
    f.cmdline_args = f.cmdline.split()
    try:
        f.uptime_s = float((ex.read_text("/proc/uptime") or "0 0").split()[0])
    except (ValueError, IndexError):
        f.uptime_s = 0.0
    f.hostname = (ex.read_text("/etc/hostname") or "").strip()


#: XDG_CURRENT_DESKTOP is a machine token ("XFCE", "ubuntu:GNOME"), while a
#: report should show the name a human would recognise ("Xfce").
DESKTOP_NAMES = {
    "xfce": "Xfce",
    "x-cinnamon": "Cinnamon",
    "cinnamon": "Cinnamon",
    "mate": "MATE",
    "lxqt": "LXQt",
    "lxde": "LXDE",
    "kde": "KDE Plasma",
    "gnome": "GNOME",
    "unity": "Unity",
    "budgie:gnome": "Budgie",
    "pop:gnome": "GNOME",
    "ubuntu:gnome": "GNOME",
    "deepin": "Deepin",
    "pantheon": "Pantheon",
}


def _pretty_desktop(token: str) -> str:
    """Turn a session token into the environment's own spelling."""
    token = (token or "").strip()
    if not token:
        return ""
    if token.lower() in DESKTOP_NAMES:
        return DESKTOP_NAMES[token.lower()]
    tail = token.split(":")[-1]
    return DESKTOP_NAMES.get(tail.lower(), tail)


def _collect_desktop(f: Facts) -> None:
    """Detect the desktop environment from the running session (not guesses)."""
    env = os.environ.get("XDG_CURRENT_DESKTOP", "")
    session = os.environ.get("DESKTOP_SESSION", "")
    if env:
        f.desktop = _pretty_desktop(env)
    elif session:
        f.desktop = _pretty_desktop(session)
    # Fall back to evidence: Xfce binaries present in the session.
    if not f.desktop:
        for proc in _list_process_cmdlines(limit=200):
            base = os.path.basename(proc.split()[0]) if proc else ""
            if base in ("xfce4-session", "xfwm4", "xfce4-panel"):
                f.desktop = "Xfce"
                break
    if f.desktop_is_xfce():
        v = ex.run(["xfce4-panel", "--version"], timeout=5)
        m = re.search(r"(\d+\.\d+(\.\d+)?)", v.out)
        if m:
            f.desktop_version = m.group(1)


def _collect_cpu(f: Facts) -> None:
    raw = ex.read_text("/proc/cpuinfo") or ""
    models: Dict[str, int] = {}
    for block in raw.split("\n\n"):
        if not block.strip():
            continue
        kv = {}
        for line in block.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                kv[k.strip()] = v.strip()
        if "model name" in kv:
            models[kv["model name"]] = models.get(kv["model name"], 0) + 1
            f.cpu_model = kv.get("model name", "")
            f.cpu_vendor = kv.get("vendor_id", "")
            f.cpu_family = kv.get("cpu family", "")
            f.cpu_model_id = kv.get("model", "")
            f.cpu_microcode = kv.get("microcode", "")
            try:
                f.cpu_max_mhz = max(f.cpu_max_mhz, float(kv.get("cpu MHz", 0) or 0))
            except ValueError:
                pass
            flags = kv.get("flags", "").split()
            if flags:
                f.cpu_flags = set(flags)
    f.cpu_threads = sum(models.values()) if models else (os.cpu_count() or 1)
    # Physical cores: count distinct core_id values under
    # /sys/devices/system/cpu/cpuN/topology/.  A dual-core AMD A6-9225 has no
    # SMT, but counting properly means hyper-threaded CPUs are not reported as
    # having twice the capacity they actually do.
    logical = [c for c in ex.listdir("/sys/devices/system/cpu")
               if re.fullmatch(r"cpu\d+", c)]
    core_ids = set()
    for c in logical:
        cid = ex.read_text(f"/sys/devices/system/cpu/{c}/topology/core_id")
        if cid and cid.strip().isdigit():
            core_ids.add(cid.strip())
    if not logical:
        f.cpu_threads = max(1, f.cpu_threads)
        f.cpu_cores = f.cpu_threads
    else:
        f.cpu_threads = len(logical)
        f.cpu_cores = len(core_ids) if core_ids else len(logical)
    f.cpu_cores = max(1, f.cpu_cores)
    # cpufreq
    gov = ex.read_text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    drv = ex.read_text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver")
    if gov:
        f.cpu_governor = gov.strip()
    if drv:
        f.cpu_driver = drv.strip()
    if not f.cpu_max_mhz:
        mx = ex.read_text("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
        if mx and mx.strip().isdigit():
            f.cpu_max_mhz = int(mx.strip()) / 1000.0


def _collect_memory(f: Facts) -> None:
    for line in ex.read_lines("/proc/meminfo", []):
        m = re.match(r"^(\w+):\s+(\d+)\s*kB", line)
        if m:
            f.meminfo[m.group(1)] = int(m.group(2))
    la = (ex.read_text("/proc/loadavg") or "").split()
    try:
        f.loadavg = [float(x) for x in la[:3]]
    except ValueError:
        f.loadavg = [0.0, 0.0, 0.0]
    for line in ex.read_lines("/proc/stat", []):
        if line.startswith("cpu "):
            parts = line.split()
            if len(parts) > 5:
                try:
                    f.stat_iowait = int(parts[5])
                except ValueError:
                    pass
            break


def _collect_dmi(f: Facts) -> None:
    base = "/sys/devices/virtual/dmi/id"
    if not ex.isdir(base):
        # Some kernels expose it elsewhere; try the class path too.
        base = "/sys/class/dmi/id"
    if not ex.isdir(base):
        return
    mp = MachineProfile()
    mp.vendor = (ex.read_text(f"{base}/sys_vendor") or "").strip()
    mp.product = (ex.read_text(f"{base}/product_name") or "").strip()
    mp.version = (ex.read_text(f"{base}/product_version") or "").strip()
    mp.serial = (ex.read_text(f"{base}/product_serial") or "").strip()
    mp.bios_version = (ex.read_text(f"{base}/bios_version") or "").strip()
    mp.chassis = (ex.read_text(f"{base}/chassis_type") or "").strip()
    mp.detected = bool(mp.vendor or mp.product)
    f.machine = mp


def _sysfs_int(path: str, default: int = 0) -> int:
    v = ex.read_text(path)
    try:
        return int((v or "").strip())
    except ValueError:
        return default


def _collect_block(f: Facts) -> None:
    for name in ex.listdir("/sys/block"):
        if name.startswith(("loop", "ram", "zram", "sr", "fd", "dm-")):
            continue
        base = f"/sys/block/{name}"
        removable = _sysfs_int(f"{base}/removable", 0)
        info: Dict[str, Any] = {
            "name": name,
            "type": "disk" if not re.match(r".*\d+$", name) else "part",
            "rotational": _sysfs_int(f"{base}/queue/rotational", 0) == 1,
            "removable": bool(removable),
            "size_sectors": _sysfs_int(f"{base}/size", 0),
            "scheduler": (ex.read_text(f"{base}/queue/scheduler") or "").strip(),
            "model": (ex.read_text(f"{base}/device/model") or "").strip(),
            "vendor": (ex.read_text(f"{base}/device/vendor") or "").strip(),
            "stat": (ex.read_text(f"{base}/stat") or "").strip(),
        }
        info["size_gb"] = round(info["size_sectors"] * 512 / 1e9, 1)
        f.block_devices.append(info)
    # Mounts: /proc/mounts (escaped spaces as \040)
    for line in ex.read_lines("/proc/mounts", []):
        parts = line.split()
        if len(parts) < 3:
            continue
        f.mounts.append({
            "device": parts[0].replace("\\040", " "),
            "mountpoint": parts[1].replace("\\040", " "),
            "fstype": parts[2],
            "options": parts[3] if len(parts) > 3 else "",
        })


def _list_process_cmdlines(limit: int = 400) -> List[str]:
    out: List[str] = []
    try:
        pids = [p for p in ex.listdir("/proc") if p.isdigit()]
    except OSError:
        return out
    for pid in pids[:limit]:
        raw = ex.read_bytes(f"/proc/{pid}/cmdline", 4096)
        if not raw:
            continue
        out.append(raw.replace(b"\0", b" ").decode("utf-8", "replace").strip())
    return out


def parse_dpkg_status(status: str) -> Dict[str, str]:
    """Parse the dpkg status database body into {package: two-letter code}."""
    packages: Dict[str, str] = {}
    name = None
    for line in status.splitlines():
        if line.startswith("Package:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Status:") and name:
            bits = line.split(":", 1)[1].strip().split()
            code = ""
            if len(bits) >= 3:
                want, _flag, state_s = bits[0], bits[1], bits[2]
                w = {"install": "i", "hold": "h", "deinstall": "r", "purge": "p"}.get(want, "u")
                s = {"installed": "i", "config-files": "c", "not-installed": "n",
                     "unpacked": "U", "half-configured": "F", "half-installed": "H",
                     "triggers-awaited": "W", "triggers-pending": "t"}.get(state_s, "?")
                code = w + s
            packages[name] = code
            name = None
    return packages


def read_dpkg_status() -> Dict[str, str]:
    """Re-read /var/lib/dpkg/status.

    Exposed separately so a repair can verify against the *live* package
    database instead of the snapshot taken during the scan.
    """
    text = ex.read_text("/var/lib/dpkg/status")
    if text is None:
        return {}
    return parse_dpkg_status(text)


def _collect_packages(f: Facts) -> None:
    """Parse /var/lib/dpkg/status -- offline, fast, no subprocess."""
    parsed = read_dpkg_status()
    if parsed:
        f.packages.update(parsed)
        return
    status = ex.read_text("/var/lib/dpkg/status")
    if status is None:
        out = ex.run(["dpkg-query", "-W", "-f=${Package} ${Status}\\n"], timeout=20)
        if out.ok:
            for line in out.lines:
                parts = line.split()
                if len(parts) >= 2:
                    f.packages[parts[0]] = "ii" if "installed" in line else " ".join(parts[1:])
        return
    name = None
    for line in status.splitlines():
        if line.startswith("Package:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Status:") and name:
            st = line.split(":", 1)[1].strip()
            # "install ok installed" -> ii
            bits = st.split()
            code = ""
            if len(bits) >= 3:
                want, _flag, state_s = bits[0], bits[1], bits[2]
                w = {"install": "i", "hold": "h", "deinstall": "r", "purge": "p"}.get(want, "u")
                s = {"installed": "i", "config-files": "c", "not-installed": "n",
                     "unpacked": "U", "half-configured": "F", "half-installed": "H",
                     "triggers-awaited": "W", "triggers-pending": "t"}.get(state_s, "?")
                code = w + s
            f.packages[name] = code
            name = None


def _collect_modules(f: Facts) -> None:
    for line in ex.read_lines("/proc/modules", []):
        f.modules.add(line.split()[0])


def _collect_user(f: Facts) -> None:
    from . import privileges
    f.user = privileges.current_user()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

_COLLECTORS = (
    _collect_os, _collect_desktop, _collect_cpu, _collect_memory,
    _collect_dmi, _collect_block, _collect_packages, _collect_modules,
    _collect_user,
)


def collect() -> Facts:
    f = Facts()
    for fn in _COLLECTORS:
        try:
            fn(f)
        except Exception as exc:  # a broken fact must never abort a scan
            import logging
            logging.getLogger("nexus.facts").warning("collector %s failed: %s", fn.__name__, exc)
    return f
