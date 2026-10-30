"""
nexus_doctor.checks.software_errors
===================================

Errors recorded by the system itself: the journal, package database integrity,
crash dumps and the X session log.

Rather than dumping hundreds of log lines, this module groups them into
recognisable failure classes and counts them.  A single error is noise; the
same error 400 times is a diagnosis.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Tuple

from ..core import executil as ex
from ..core import privileges
from ..core.engine import ScanContext, register
from ..core.models import Category, Confidence, Evidence, Finding, Severity
from .common import count_matches, human_bytes, journal_messages, match_lines, result

ERROR_BUCKETS: List[Tuple[str, str, str]] = [
    ("storage", r"I/O error|ata\d|EXT4-fs error|buffer I/O|hard resetting link|"
                r"blk_update_request|critical medium error",
     "Disk or filesystem errors"),
    ("memory", r"Out of memory|oom-kill|killed process|Memory cgroup out of memory",
     "Out-of-memory events"),
    ("gpu", r"amdgpu|radeon|drm:|GPU hang|ring .* timeout|failed to load firmware",
     "Graphics driver or firmware errors"),
    ("usb", r"usb \d-\d|USB disconnect|device descriptor read", "USB device errors"),
    ("network", r"wlp|NetworkManager|dhclient|failed to connect|Association request",
     "Network errors"),
    ("services", r"Failed to start|failed with result|Main process exited|"
                 r"Start request repeated too quickly", "Service start failures"),
    ("crash", r"segfault|general protection fault|traps:|Call Trace:",
     "Application or kernel crashes"),
    ("thermal", r"thermal|temperature above threshold|cpu clock throttled",
     "Thermal events"),
    ("firmware", r"firmware: failed|Direct firmware load.*failed",
     "Missing firmware files"),
    ("apparmor", r"apparmor=|DENIED", "Security policy denials"),
]


def bucket_counts(lines: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for key, pattern, _label in ERROR_BUCKETS:
        out[key] = sum(1 for l in lines if re.search(pattern, l, re.I))
    return out


def dpkg_problems(facts_packages: Dict[str, str]) -> List[Tuple[str, str]]:
    """Packages that are not in the clean 'installed' state."""
    bad: List[Tuple[str, str]] = []
    for name, status in facts_packages.items():
        if status and status != "ii" and not status.startswith("ii"):
            if status == "rc":
                continue  # removed but config remains: harmless
            bad.append((name, status))
    bad.sort()
    return bad


@register("software_errors", "Software and system errors", Category.SOFTWARE,
          priority=60, description="Journal errors, broken packages, crash dumps")
def check_software_errors(ctx: ScanContext):
    f = ctx.f
    findings: List[Finding] = []
    facts: Dict[str, object] = {}

    # ------------------------------------------------------ journal errors
    lines = journal_messages(priority=3, limit=500)
    facts["journal_error_lines"] = len(lines)
    if lines:
        counts = bucket_counts(lines)
        facts["error_buckets"] = counts
        notable = {k: v for k, v in counts.items()
                   if v > 0 and k not in ("apparmor",)}
        if notable:
            total = sum(notable.values())
            samples: List[Tuple[str, str]] = []
            for key, _n in sorted(notable.items(), key=lambda kv: -kv[1])[:3]:
                pattern = next(p for k, p, _l in ERROR_BUCKETS if k == key)
                hit = match_lines(lines, [pattern], limit=2)
                samples.extend(hit)
            critical_kinds = {"storage", "memory", "crash"}
            sev = (Severity.HIGH if (critical_kinds & set(notable) and total >= 5)
                   else Severity.MEDIUM if total >= 20 else Severity.LOW)
            labels = ", ".join(f"{lab}: {counts[k]}" for k, _p, lab in ERROR_BUCKETS
                               if counts.get(k))
            findings.append(Finding(
                id="software.journal_errors",
                title=f"{total} error-level message(s) recorded since boot",
                category=Category.SOFTWARE, severity=sev,
                summary=f"Grouped by category: {labels}.",
                root_cause=("The system log records what actually went wrong. Repeated "
                            "messages of one kind point at a specific failing component."),
                impact="Depends on the category; storage and memory errors are the serious ones.",
                evidence=[Evidence(source="journalctl -p 3 -b",
                                   detail=labels,
                                   raw="\n".join(line[:200] for _p, line in samples),
                                   command="journalctl -p 3 -b --no-pager -o cat -n 500")],
                confidence=Confidence.DIRECT,
                needs_root=not lines,
                recommendations=[
                    "Look at the busiest category first; the checks for that component in "
                    "this report give the specific diagnosis.",
                    "See the full list with: journalctl -p 3 -xb",
                ],
                data={"buckets": counts},
            ))
    else:
        findings.append(Finding(
            id="software.journal_unavailable",
            title="System log is not readable by this user",
            category=Category.SOFTWARE, severity=Severity.INFO,
            summary=("The journal could not be read (the user is not in the 'adm' group, or "
                     "rsyslog is not installed), so error history is unavailable."),
            root_cause="Log access is restricted to the adm group and root by default.",
            evidence=[Evidence(source="journalctl -p 3 -b", detail="no output or permission denied",
                               command="journalctl -p 3 -b -n 5")],
            confidence=Confidence.DIRECT, needs_root=True, manual=True,
            recommendations=["Run the scan as administrator to include the system log."]))

    # ------------------------------------------------ package database
    bad = dpkg_problems(f.packages)
    facts["dpkg_problems"] = bad
    if bad:
        audit = ex.run(["dpkg", "--audit"], timeout=30)
        findings.append(Finding(
            id="software.dpkg_broken",
            title=f"{len(bad)} package(s) are in an incomplete state",
            category=Category.SOFTWARE, severity=Severity.HIGH,
            summary=("Packages that are half-installed or half-configured block other "
                     "packages from installing or upgrading, and the applications they "
                     "provide may not start."),
            root_cause="An installation or upgrade was interrupted (power loss, closed lid, "
                       "or a full disk).",
            impact="Updates fail; some applications are broken.",
            evidence=[Evidence(source="/var/lib/dpkg/status",
                               detail="; ".join(f"{n} [{s}]" for n, s in bad[:10]),
                               raw=(audit.out or "")[:800] or
                                   "\n".join(f"{n}\t{s}" for n, s in bad),
                               command="dpkg --audit")],
            confidence=Confidence.DIRECT,
            recommendations=[
                "Run: sudo dpkg --configure -a   (safe, offline, fixes most cases)",
                "Then: sudo apt-get install -f   (may need an internet connection)",
            ],
            repair_ids=["software.fix_dpkg"],
            data={"packages": [n for n, _s in bad]},
        ))

    # ------------------------------------------------------- crash dumps
    coredump_dirs = ["/var/lib/systemd/coredump", "/var/crash"]
    dumps: List[Tuple[str, int]] = []
    for d in coredump_dirs:
        if ex.isdir(d):
            size = ex.dir_size(d, max_entries=2000)
            if size > 0:
                dumps.append((d, size))
    facts["crash_dumps"] = dumps
    if dumps:
        total = sum(s for _d, s in dumps)
        findings.append(Finding(
            id="software.coredumps",
            title=f"Crash dumps occupy {human_bytes(total)}",
            category=Category.SOFTWARE, severity=Severity.MEDIUM,
            summary=(f"Applications have crashed and left core dumps in "
                     f"{', '.join(d for d, _s in dumps)}."),
            root_cause="One or more applications crashed (segfault, abort, or OOM kill).",
            impact="Disk space consumed; the crashing application is unreliable.",
            evidence=[Evidence(source=", ".join(d for d, _s in dumps),
                               detail=f"{human_bytes(total)} total",
                               command="coredumpctl list || ls -lh /var/crash")],
            confidence=Confidence.MEASURED,
            recommendations=[
                "See what crashed with: coredumpctl list",
                "If it is always the same application, reinstall it: sudo apt install --reinstall <package>",
                "Clear them with: sudo coredumpctl flush (or delete the files after review).",
            ],
            manual=True,
        ))

    # -------------------------------------------------- X session errors
    home = privileges.user_home()
    xsession = os.path.join(home, ".xsession-errors")
    size = 0
    if ex.isfile(xsession):
        try:
            size = os.path.getsize(ex.syspath(xsession))
        except OSError:
            size = 0
    facts["xsession_errors_bytes"] = size
    if size > 5 * 1024 * 1024:
        tail = (ex.read_text(xsession) or "").splitlines()[-12:]
        findings.append(Finding(
            id="software.xsession_errors",
            title=f"The X session error log has grown to {human_bytes(size)}",
            category=Category.SOFTWARE, severity=Severity.LOW,
            summary=("Applications print warnings to ~/.xsession-errors. A large file means "
                     "something is complaining repeatedly on every login."),
            root_cause="A startup application or panel plugin is logging errors continuously.",
            impact="Disk churn on a mechanical disk; hides real problems.",
            evidence=[Evidence(source=xsession, detail=f"{human_bytes(size)}",
                               raw="\n".join(l[:160] for l in tail),
                               command=f"tail -20 {xsession}")],
            confidence=Confidence.MEASURED,
            recommendations=["Read the tail of the file to identify the repeating message."],
            manual=True,
        ))

    if not findings:
        findings.append(Finding(
            id="software.ok",
            title="No significant system errors recorded",
            category=Category.SOFTWARE, severity=Severity.OK,
            summary="The journal shows no error-level messages and the package database is consistent.",
            evidence=[Evidence(source="journalctl -p 3 -b", detail="0 error-level messages",
                               command="journalctl -p 3 -b")],
            confidence=Confidence.DIRECT))

    return result("software_errors", "Software and system errors", Category.SOFTWARE,
                  findings, facts=facts)
