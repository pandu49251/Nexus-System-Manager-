"""
nexus_doctor.core.models
========================

Data types shared by the diagnostic engine, the repair engine, the GUI and the
report generator.

Design rule: **a finding without evidence is not a finding.**  ``Finding``
objects must carry at least one ``Evidence`` item built from a real command,
a real sysfs file, or an explicitly-stated measurement.  ``Finding.confidence``
expresses how directly the evidence supports the conclusion, and the report
shows it, so a user is never misled by a guess presented as fact.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"   # data loss / imminent failure
    HIGH = "high"           # severe, affects usability or risks data
    MEDIUM = "medium"       # noticeable degradation
    LOW = "low"             # minor / cosmetic
    INFO = "info"           # context, no action needed
    OK = "ok"               # explicitly checked and healthy

    @property
    def rank(self) -> int:
        return {
            "critical": 0, "high": 1, "medium": 2,
            "low": 3, "info": 4, "ok": 5,
        }[self.value]

    @property
    def label(self) -> str:
        return self.value.upper()

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


class Category(str, Enum):
    STORAGE = "storage"
    FILESYSTEM = "filesystem"
    MEMORY = "memory"
    CPU = "cpu"
    THERMAL = "thermal"
    BATTERY = "battery"
    GRAPHICS = "graphics"
    INPUT = "input"
    SERVICES = "services"
    SOFTWARE = "software"
    KERNEL = "kernel"
    BOOT = "boot"
    POWER = "power"
    GENERAL = "general"


CATEGORY_LABELS = {
    "storage": "Storage / HDD health",
    "filesystem": "Filesystem & disk space",
    "memory": "Memory & swap",
    "cpu": "Processor & load",
    "thermal": "Temperature & throttling",
    "battery": "Battery & power",
    "graphics": "Graphics & drivers",
    "input": "Keyboard & input devices",
    "services": "Services & startup",
    "software": "Software & system errors",
    "kernel": "Kernel, modules & drivers",
    "boot": "Boot performance",
    "power": "Power management",
    "general": "General",
}


class Confidence(str, Enum):
    """How directly the evidence supports the conclusion."""
    MEASURED = "measured"    # we measured it ourselves, right now
    DIRECT = "direct"        # reported verbatim by an authoritative tool
    INFERRED = "inferred"    # derived by combining two or more signals
    SUSPECTED = "suspected"  # plausible; evidence is circumstantial


@dataclass
class Evidence:
    """A single, reproducible piece of proof backing a finding."""
    source: str                      # human-readable origin, e.g. "smartctl -A /dev/sda"
    detail: str                      # what it told us
    raw: str = ""                    # verbatim excerpt (for the report / audit)
    command: str = ""                # exact argv, so the user can re-run it
    root_required: bool = False      # true if it needs administrator rights

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str                                   # stable id, e.g. "memory.no_swap"
    title: str
    category: Category
    severity: Severity
    summary: str                              # one or two sentences
    root_cause: str = ""                      # the *why*, not just the *what*
    impact: str = ""                          # what the user actually experiences
    evidence: List[Evidence] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    repair_ids: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.DIRECT
    manual: bool = False                      # no safe automatic repair exists
    data: Dict[str, Any] = field(default_factory=dict)   # machine-readable payload
    needs_root: bool = False                  # evidence incomplete without root
    needs_network: bool = False
    reboot_required: bool = False             # the fix only takes effect after a reboot
    tags: List[str] = field(default_factory=list)

    def add(self, source: str, detail: str, raw: str = "", command: str = "",
            root_required: bool = False) -> "Finding":
        self.evidence.append(Evidence(source, detail, raw, command, root_required))
        return self

    @property
    def severity_rank(self) -> int:
        return self.severity.rank

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["category_label"] = CATEGORY_LABELS.get(self.category.value, self.category.value)
        return d


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: Category
    findings: List[Finding] = field(default_factory=list)
    duration_ms: int = 0
    state: str = "ok"          # ok | degraded | skipped | failed
    notes: str = ""            # why it was degraded/skipped
    facts: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category.value,
            "duration_ms": self.duration_ms,
            "state": self.state,
            "notes": self.notes,
            "facts": self.facts,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class MachineProfile:
    """Identity of the machine being diagnosed (never guessed, read from DMI)."""
    vendor: str = ""
    product: str = ""
    version: str = ""
    serial: str = ""
    bios_version: str = ""
    chassis: str = ""
    detected: bool = False

    def describe(self) -> str:
        if not self.detected:
            return "Unknown system (DMI not readable)"
        bits = [b for b in (self.vendor, self.product, self.version) if b]
        return " ".join(bits)


@dataclass
class ScanReport:
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    hostname: str = ""
    machine: MachineProfile = field(default_factory=MachineProfile)
    distro: str = ""
    desktop: str = ""
    kernel: str = ""
    cpu_model: str = ""
    cpu_cores: int = 0
    mem_total_mb: int = 0
    root_disk: str = ""
    results: List[CheckResult] = field(default_factory=list)
    #: The Facts snapshot the scan was taken against (kept so repairs can
    #: reason about the same machine state the findings describe).
    facts: Any = None
    deep: bool = False
    run_as: str = ""
    euid: int = -1

    @property
    def findings(self) -> List[Finding]:
        out: List[Finding] = []
        for r in self.results:
            out.extend(r.findings)
        return out

    def sorted_findings(self) -> List[Finding]:
        """Findings ordered most severe first, then by category then title."""
        return sorted(self.findings,
                      key=lambda f: (f.severity.rank,
                                     CATEGORY_LABELS.get(f.category.value, ""),
                                     f.title))

    def by_severity(self, *sev: Severity) -> List[Finding]:
        wanted = {s for s in sev}
        return [f for f in self.findings if f.severity in wanted]

    def counts(self) -> Dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def actionables(self) -> List[Finding]:
        return [f for f in self.findings
                if f.severity.rank <= Severity.LOW.rank and (f.repair_ids or f.recommendations)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "nexus-system-doctor/scan",
            "schema_version": 1,
            "started": self.started,
            "finished": self.finished,
            "duration_s": round(self.finished - self.started, 2),
            "hostname": self.hostname,
            "distro": self.distro,
            "desktop": self.desktop,
            "kernel": self.kernel,
            "cpu_model": self.cpu_model,
            "cpu_cores": self.cpu_cores,
            "mem_total_mb": self.mem_total_mb,
            "root_disk": self.root_disk,
            "deep_scan": self.deep,
            "run_as": self.run_as,
            "machine": asdict(self.machine),
            "counts": self.counts(),
            "results": [r.to_dict() for r in self.results],
        }


# --------------------------------------------------------------------------
# Repair model
# --------------------------------------------------------------------------


class Risk(str, Enum):
    LOW = "low"          # fully reversible, no data touched
    MEDIUM = "medium"    # changes system configuration; backed up + reversible
    HIGH = "high"        # may remove files or needs a reboot; explicit consent
    MANUAL = "manual"    # we will not do it automatically - instructions only


@dataclass
class RepairOutcome:
    """Result of applying *or* verifying a repair."""
    ok: bool
    message: str = ""
    before: str = ""
    after: str = ""
    details: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RepairResult:
    repair_id: str
    title: str
    attempted: bool = False
    applied: bool = False
    verified: bool = False
    state: str = "pending"     # pending | applied | failed | skipped | verified
    message: str = ""
    verify_before: str = ""
    verify_after: str = ""
    backups: List[str] = field(default_factory=list)
    rollback: str = ""         # human-readable undo instructions
    duration_ms: int = 0
    timestamp: float = field(default_factory=time.time)
    risk: str = ""
    commands: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Repair:
    """Base class for a repair action.

    Subclasses implement :meth:`available` (can it apply here?),
    :meth:`apply` (do it) and :meth:`verify` (prove the desired state now
    holds).  ``verify`` is run **before** and **after** ``apply``; a repair is
    reported as successful only if the post-verification passes.  This is the
    core safety property of the application: no repair is ever assumed to have
    worked.
    """

    id: str = "base"
    title: str = "Untitled repair"
    description: str = ""
    risk: Risk = Risk.LOW
    requires_root: bool = False
    requires_network: bool = False
    requires_gui: bool = False        # needs an X session (xset/xfconf)
    reboot_required: bool = False
    #: False for repairs that delete data which cannot be recreated (clearing
    #: a cache, configuring a package).  The UI shows this before applying.
    undoable: bool = True
    fixes: List[str] = field(default_factory=list)   # finding ids this addresses

    # -- interface ---------------------------------------------------------
    def available(self, ctx: "ScanContext") -> bool:          # noqa: F821
        """True if this repair is meaningful on this machine right now."""
        return True

    def why(self, ctx: "ScanContext") -> str:                 # noqa: F821
        """Short explanation shown next to the checkbox."""
        return self.description

    def steps(self, ctx: "ScanContext") -> List[str]:         # noqa: F821
        """Human-readable list of what will be done (shown before applying)."""
        return [self.description]

    def apply(self, ctx: "ScanContext") -> RepairOutcome:     # noqa: F821
        raise NotImplementedError

    def verify(self, ctx: "ScanContext") -> RepairOutcome:    # noqa: F821
        raise NotImplementedError

    def rollback(self, ctx: "ScanContext") -> RepairOutcome:  # noqa: F821
        return RepairOutcome(False, "No automatic rollback for this repair.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "risk": self.risk.value,
            "requires_root": self.requires_root,
            "requires_network": self.requires_network,
            "requires_gui": self.requires_gui,
            "reboot_required": self.reboot_required,
            "fixes": list(self.fixes),
        }
