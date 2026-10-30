"""
nexus_doctor.checks.storage_space
=================================

Disk space and the things that quietly fill it up.

A nearly-full mechanical disk is dramatically slower than a half-empty one:
the filesystem has to hunt for free blocks, and fragmentation increases as
space runs out.  Keeping 20% free is one of the cheapest performance wins
available, which is why this check also reports *what* is using the space so
the user can decide.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from ..core import executil as ex
from ..core import privileges
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import human_bytes, pct, result

CANDIDATE_MOUNTS = ("/", "/home", "/boot", "/boot/efi", "/tmp", "/var", "/usr")


def usage(mountpoint: str) -> Optional[Dict[str, float]]:
    """Filesystem usage via statvfs (no subprocess, no 'df' parsing)."""
    path = ex.syspath(mountpoint)
    try:
        st = ex.statvfs(mountpoint)
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    free = st.f_bfree * st.f_frsize
    avail = st.f_bavail * st.f_frsize
    used = total - free
    itotal, ifree = st.f_files, st.f_ffree
    return {
        "total": total, "free": free, "avail": avail, "used": used,
        "used_pct": pct(used, total, 1),
        "avail_pct": pct(avail, total, 1),
        "inodes_total": itotal, "inodes_free": ifree,
        "inodes_used_pct": pct(itotal - ifree, itotal, 1) if itotal else 0.0,
    }


def journal_usage() -> Tuple[Optional[int], str]:
    """Size of the systemd journal; returns (bytes, human-readable source)."""
    r = ex.run(["journalctl", "--disk-usage"], timeout=12)
    if r.ok:
        m = re.search(r"([\d.]+)\s*([KMGT]?)B?(?![A-Za-z])", r.out)
        if m:
            mult = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
            try:
                return int(float(m.group(1)) * mult[m.group(2)]), "journalctl --disk-usage"
            except (ValueError, KeyError):
                pass
    if ex.isdir("/var/log/journal"):
        return ex.dir_size("/var/log/journal"), "/var/log/journal (directory size)"
    return None, ""


def top_large_files(directory: str, n: int = 5) -> List[Tuple[str, int]]:
    """Largest regular files under *directory* (bounded scan, no recursion depth limit)."""
    found: List[Tuple[str, int]] = []
    root = ex.syspath(directory)
    for dirpath, _dirs, files in os.walk(root, onerror=lambda _e: None):
        for name in files:
            try:
                full = os.path.join(dirpath, name)
                st = os.lstat(full)
                if st.st_size > 1_000_000:
                    found.append((full.replace(ex.SYSROOT, "") if ex.SYSROOT else full,
                                  st.st_size))
            except OSError:
                continue
        if len(found) > 400:
            break
    found.sort(key=lambda t: t[1], reverse=True)
    return found[:n]


@register("storage_space", "Disk space usage", Category.FILESYSTEM, priority=12,
          description="Free space, inodes, journal, package cache, caches")
def check_storage_space(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}
    home = privileges.user_home()

    mounts_seen = {m["mountpoint"] for m in f.mounts}
    checked: Dict[str, Dict[str, float]] = {}
    for mp in CANDIDATE_MOUNTS:
        if mp not in mounts_seen:
            continue
        u = usage(mp)
        if u:
            checked[mp] = u
    if "/" not in checked:
        u = usage("/")
        if u:
            checked["/"] = u
    facts["usage"] = {k: {kk: vv for kk, vv in v.items()} for k, v in checked.items()}

    # ------------------------------------------------------ free space
    for mp, u in checked.items():
        facts[f"free_pct{mp}"] = u["avail_pct"]
        if u["avail_pct"] >= 20:
            continue
        if u["avail_pct"] < 5:
            sev, word = Severity.CRITICAL, "critically full"
        elif u["avail_pct"] < 10:
            sev, word = Severity.HIGH, "nearly full"
        else:
            sev, word = Severity.MEDIUM, "getting full"
        gb_free = u["avail"] / 1e9
        fstype = next((m["fstype"] for m in f.mounts if m["mountpoint"] == mp), "?")
        rotational = f.is_hdd(f.root_device())
        findings.append(Finding(
            id=f"space.low_{mp.strip('/') or 'root'}",
            title=f"{mp} is {word}: only {human_bytes(u['avail'])} free ({u['avail_pct']}%)",
            category=Category.FILESYSTEM,
            severity=Severity.CRITICAL if (sev is Severity.CRITICAL and mp == "/") else sev,
            summary=(f"The filesystem mounted at {mp} has {human_bytes(u['avail'])} of "
                     f"{human_bytes(u['total'])} free."),
            root_cause=("Free space below 20%. On a mechanical disk this is self-reinforcing: "
                        "the allocator has to search harder for free blocks and files become "
                        "more fragmented, so every read takes longer."
                        if rotational else
                        "Free space below 20%; filesystems need headroom to allocate efficiently."),
            impact=("Slower writes and reads, applications failing to save, and on a mechanical "
                    "disk a very noticeable overall slowdown."),
            evidence=[Evidence(source=f"statvfs({mp})",
                               detail=f"size {human_bytes(u['total'])}, used {human_bytes(u['used'])} "
                                      f"({u['used_pct']}%), available {human_bytes(u['avail'])} "
                                      f"({u['avail_pct']}%), filesystem {fstype}",
                               command=f"df -h {mp}")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "Empty the trash (Xfce keeps deleted files in ~/.local/share/Trash).",
                "Remove old package archives and shrink the system journal (see the cleanup repairs below).",
                "Move large media files to an external drive.",
            ],
            repair_ids=["cleanup.apt_cache", "cleanup.journal", "cleanup.thumbnails"],
            data={"mount": mp, "avail_pct": u["avail_pct"]},
        ))

        # inodes
        if u["inodes_used_pct"] >= 90:
            findings.append(Finding(
                id=f"space.inodes_{mp.strip('/') or 'root'}",
                title=f"{mp} is running out of inodes ({u['inodes_used_pct']}% used)",
                category=Category.FILESYSTEM,
                severity=Severity.HIGH if u["inodes_used_pct"] >= 98 else Severity.MEDIUM,
                summary=("The filesystem can still store data but is nearly out of file "
                         "slots, so creating new files will fail with 'No space left on device' "
                         "even though space appears free."),
                root_cause="Very large numbers of tiny files (mail caches, thumbnails, node_modules, session data).",
                impact="Writes fail with confusing errors; applications misbehave.",
                evidence=[Evidence(source=f"statvfs({mp})",
                                   detail=f"{u['inodes_free']} of {u['inodes_total']} inodes free",
                                   command=f"df -i {mp}")],
                confidence=Confidence.MEASURED,
                recommendations=["Find the directory with the most files and remove what you do not need."],
                repair_ids=["cleanup.thumbnails"],
            ))

    # ------------------------------------------------------ systemd journal
    jsize, jsrc = journal_usage()
    facts["journal_bytes"] = jsize
    if jsize and jsize > 300 * 1024 * 1024:
        findings.append(Finding(
            id="space.journal_large",
            title=f"System logs occupy {human_bytes(jsize)}",
            category=Category.FILESYSTEM,
            severity=Severity.MEDIUM if jsize > 1024 ** 3 else Severity.LOW,
            summary=(f"The systemd journal has grown to {human_bytes(jsize)} ({jsrc}). "
                     f"Every disk write elsewhere gets slower on a nearly-full mechanical disk."),
            root_cause="Logs are retained without a size cap (default limits are generous).",
            impact="Wasted space and slower boot-time log rotation on a mechanical disk.",
            evidence=[Evidence(source=jsrc, detail=f"journal size = {human_bytes(jsize)}",
                               command="journalctl --disk-usage")],
            confidence=Confidence.MEASURED,
            recommendations=["Limit the journal to ~200 MB and keep 14 days of history."],
            repair_ids=["cleanup.journal"],
            data={"bytes": jsize},
        ))

    # --------------------------------------------------- package cache
    cache_dir = "/var/cache/apt/archives"
    cache_size = ex.dir_size(cache_dir) if ex.isdir(cache_dir) else 0
    facts["apt_cache_bytes"] = cache_size
    if cache_size > 200 * 1024 * 1024:
        findings.append(Finding(
            id="space.apt_cache_large",
            title=f"Downloaded package files occupy {human_bytes(cache_size)}",
            category=Category.FILESYSTEM,
            severity=Severity.LOW,
            summary=(f"{human_bytes(cache_size)} of .deb files are cached in {cache_dir}. "
                     f"They are only needed to reinstall packages without re-downloading."),
            root_cause="apt-get clean/autoclean has not been run recently.",
            impact="Wasted disk space; no performance effect while unused.",
            evidence=[Evidence(source=cache_dir, detail=f"{human_bytes(cache_size)} in .deb archives",
                               command=f"du -sh {cache_dir}")],
            confidence=Confidence.MEASURED,
            recommendations=["Run 'apt-get clean' - it is completely safe and reversible by re-downloading."],
            repair_ids=["cleanup.apt_cache"],
            data={"bytes": cache_size},
        ))

    # ------------------------------------------------------ user caches
    thumb_dir = os.path.join(home, ".cache/thumbnails")
    thumb_size = ex.dir_size(thumb_dir) if ex.isdir(thumb_dir) else 0
    facts["thumbnail_bytes"] = thumb_size
    if thumb_size > 400 * 1024 * 1024:
        findings.append(Finding(
            id="space.thumbnails_large",
            title=f"Thumbnail cache has grown to {human_bytes(thumb_size)}",
            category=Category.FILESYSTEM,
            severity=Severity.LOW,
            summary=(f"{human_bytes(thumb_size)} of image thumbnails are stored in "
                     f"{thumb_dir}. On a mechanical disk a very large thumbnail directory "
                     f"makes the file manager slow to open image folders."),
            root_cause="Thumbnails are cached indefinitely by default.",
            impact="Slow folder browsing in Thunar; wasted space. They are regenerated on demand.",
            evidence=[Evidence(source=thumb_dir, detail=f"{human_bytes(thumb_size)} cached",
                               command=f"du -sh {thumb_dir}")],
            confidence=Confidence.MEASURED,
            recommendations=["Clear the thumbnail cache; it is rebuilt automatically."],
            repair_ids=["cleanup.thumbnails"],
            data={"bytes": thumb_size},
        ))

    # --------------------------------------------------------- /var/log
    log_size = ex.dir_size("/var/log", max_entries=8000) if ex.isdir("/var/log") else 0
    facts["var_log_bytes"] = log_size
    if log_size > 1024 ** 3:
        big = top_large_files("/var/log", 5)
        findings.append(Finding(
            id="space.varlog_large",
            title=f"/var/log occupies {human_bytes(log_size)}",
            category=Category.FILESYSTEM,
            severity=Severity.LOW,
            summary=f"Log files total {human_bytes(log_size)}.",
            root_cause="Unrotated or rapidly growing logs.",
            evidence=[Evidence(source="/var/log", detail=f"{human_bytes(log_size)} total",
                               raw="\n".join(f"{human_bytes(s)}  {p}" for p, s in big),
                               command="du -sh /var/log"),
                      Evidence(source="largest log files",
                               detail=", ".join(f"{os.path.basename(p)} {human_bytes(s)}"
                                                for p, s in big) or "n/a",
                               command="du -a /var/log | sort -nr | head")],
            confidence=Confidence.MEASURED,
            recommendations=["Check whether a service is logging errors in a loop (see Software & system errors)."],
            repair_ids=["cleanup.journal"],
        ))

    # --------------------------------------------------------- trash
    trash = os.path.join(home, ".local/share/Trash")
    trash_size = ex.dir_size(trash) if ex.isdir(trash) else 0
    facts["trash_bytes"] = trash_size
    if trash_size > 500 * 1024 * 1024:
        findings.append(Finding(
            id="space.trash_large",
            title=f"The trash contains {human_bytes(trash_size)}",
            category=Category.FILESYSTEM,
            severity=Severity.LOW,
            summary="Deleted files still occupy disk space until the trash is emptied.",
            root_cause="Files deleted in Thunar go to the trash rather than being removed.",
            evidence=[Evidence(source=trash, detail=f"{human_bytes(trash_size)} in trash",
                               command=f"du -sh {trash}")],
            confidence=Confidence.MEASURED,
            recommendations=["Empty the trash from the Thunar desktop icon or file manager."],
            manual=True,
        ))

    if not findings:
        root_u = checked.get("/") or {}
        findings.append(Finding(
            id="space.ok",
            title="Disk space is comfortable",
            category=Category.FILESYSTEM, severity=Severity.OK,
            summary=(f"{human_bytes(root_u.get('avail', 0))} free on / "
                     f"({root_u.get('avail_pct', 0)}%) - above the 20% headroom a "
                     f"mechanical disk needs."),
            evidence=[Evidence(source="statvfs(/)",
                               detail=f"{human_bytes(root_u.get('avail', 0))} available of "
                                      f"{human_bytes(root_u.get('total', 0))}",
                               command="df -h /")],
            confidence=Confidence.MEASURED))

    return result("storage_space", "Disk space usage", Category.FILESYSTEM,
                  findings, facts=facts)
