"""
Diagnostics against the synthetic Lenovo IdeaPad S145-14AST.

The fixture machine is deliberately ill: a worn mechanical disk with real
SMART failures, 4 GB of RAM with no swap, high iowait, a stuck modifier key,
the wrong keyboard layout, a hot CPU, broken packages, failed units, a 1.4 GB
journal, ten autostart applications and a missing power-management daemon.

These tests assert that the engine finds those faults, attributes them to the
right subsystem, and backs every claim with evidence.
"""

from __future__ import annotations

import unittest

import harness

harness.use_fixture(writable=True, root=False)
from nexus_doctor.core.engine import Engine, load_checks        # noqa: E402
from nexus_doctor.core.models import Severity                   # noqa: E402
from nexus_doctor.core.repairer import all_repairs              # noqa: E402


def _scan(deep: bool = False):
    harness.use_fixture(writable=True, root=False)
    load_checks()
    return Engine(deep=deep, workers=1).run()


class FixtureScanTests(unittest.TestCase):
    """The engine must recognise the machine and find its real faults."""

    @classmethod
    def setUpClass(cls):
        cls.report = _scan()

    # ------------------------------------------------------------------
    def test_machine_is_identified(self):
        m = self.report.machine
        self.assertEqual("LENOVO", m.vendor)
        self.assertIn("81ST", m.product or "")
        # Lenovo puts the marketing model in the DMI product version field
        self.assertIn("IdeaPad S145", m.version or m.product or "")
        self.assertIn("IdeaPad S145", m.describe())
        self.assertEqual(2, self.report.cpu_cores)
        self.assertGreater(self.report.mem_total_mb, 3400)
        self.assertLess(self.report.mem_total_mb, 4096)
        self.assertIn("Mint", self.report.distro or "")
        self.assertIn("Xfce", self.report.desktop or "")
        self.assertTrue(self.report.kernel.startswith("5.15"))
        self.assertTrue(self.report.root_disk)

    def test_the_disk_is_recognised_as_mechanical(self):
        self.assertTrue(any(f.id.startswith("storage.mechanical")
                            for f in self.report.findings))

    # -- the faults the user asked us to detect -------------------------
    def test_detects_keyboard_problems(self):
        ids = {f.id for f in self.report.findings if f.category.value == "input"}
        self.assertIn("input.repeat_rate", ids, "slow key repeat must be found")
        self.assertIn("input.layout_mismatch", ids, "wrong layout must be found")
        self.assertIn("input.ps2_errors", ids, "PS/2 errors must be found")
        self.assertIn("input.stuck_key", ids, "a stuck key must be found")

    def test_detects_system_lag_and_slowness(self):
        ids = {f.id for f in self.report.findings}
        self.assertIn("cpu.iowait_high", ids)
        self.assertIn("cpu.load_high", ids)
        self.assertIn("cpu.governor_low", ids)
        self.assertIn("services.slow_boot", ids)

    def test_detects_memory_pressure(self):
        ids = {f.id for f in self.report.findings if f.category.value == "memory"}
        self.assertIn("memory.no_swap", ids)
        self.assertIn("memory.pressure", ids)
        self.assertIn("memory.oom_kills", ids)
        self.assertIn("memory.small_ram", ids)

    def test_detects_hdd_health_problems(self):
        ids = {f.id for f in self.report.findings if f.category.value == "storage"}
        for expected in ("storage.reallocated_sector_ct_sda",
                         "storage.current_pending_sector_sda",
                         "storage.reported_uncorrect_sda",
                         "storage.offline_uncorrectable_sda",
                         "storage.command_timeout_sda",
                         "storage.crc_errors_sda"):
            self.assertIn(expected, ids, f"{expected} must be reported")
        # Reallocated sectors are a genuine, imminent failure: critical.
        sev = {f.id: f.severity for f in self.report.findings}
        self.assertEqual(Severity.CRITICAL, sev["storage.reallocated_sector_ct_sda"])

    def test_detects_thermal_issues(self):
        ids = {f.id for f in self.report.findings if f.category.value == "thermal"}
        self.assertTrue(ids, "an 84 degree CPU must produce a thermal finding")

    def test_detects_battery_condition(self):
        ids = {f.id for f in self.report.findings if f.category.value == "battery"}
        self.assertTrue(any(i.startswith("battery.wear") for i in ids),
                        "a battery at 47% of design capacity must be reported")
        self.assertTrue(any(i.startswith("battery.cycles") for i in ids))

    def test_detects_graphics_driver_state(self):
        ids = {f.id for f in self.report.findings if f.category.value == "graphics"}
        self.assertTrue(ids, "the graphics check must report something")
        self.assertIn("graphics.amd_driver_ok", ids)

    def test_detects_software_errors(self):
        ids = {f.id for f in self.report.findings if f.category.value == "software"}
        self.assertIn("software.dpkg_broken", ids)
        self.assertIn("software.journal_errors", ids)

    def test_detects_failed_services_and_startup_weight(self):
        ids = {f.id for f in self.report.findings}
        self.assertIn("services.failed_units", ids)
        self.assertIn("services.many_autostart", ids)
        self.assertIn("services.indexer_running", ids)
        self.assertIn("services.unused_hw_services", ids)

    def test_detects_kernel_driver_faults(self):
        ids = {f.id for f in self.report.findings if f.category.value == "kernel"}
        self.assertTrue(ids, "a missing platform driver must be reported")

    # -- quality requirements -------------------------------------------
    def test_every_finding_is_backed_by_evidence(self):
        """No finding may exist without something that proves it."""
        unbacked = []
        for f in self.report.findings:
            if not f.evidence:
                unbacked.append(f.id)
            else:
                for ev in f.evidence:
                    if not (ev.source or "").strip():
                        unbacked.append(f"{f.id} (evidence with no source)")
        self.assertEqual([], unbacked,
                         "findings without evidence: " + ", ".join(unbacked))

    def test_every_finding_has_a_summary_and_a_recommendation(self):
        bad = []
        for f in self.report.findings:
            if not f.summary.strip():
                bad.append(f"{f.id}: no summary")
            if f.severity.rank <= Severity.LOW.rank and not f.recommendations:
                bad.append(f"{f.id}: no recommended action")
        self.assertEqual([], bad)

    def test_finding_confidence_is_declared(self):
        for f in self.report.findings:
            self.assertIsNotNone(f.confidence, f.id)
            self.assertTrue(f.confidence.value, f.id)

    def test_offered_repairs_are_real(self):
        """A finding must never point at a repair that does not exist."""
        known = {r.id for r in all_repairs()}
        dangling = []
        for f in self.report.findings:
            for rid in f.repair_ids:
                if rid not in known:
                    dangling.append(f"{f.id} -> {rid}")
        self.assertEqual([], dangling, "unknown repair ids: " + ", ".join(dangling))

    def test_no_check_crashed_or_degraded(self):
        bad = [(r.check_id, r.state, r.notes) for r in self.report.results
               if r.state not in ("ok", "skipped")]
        self.assertEqual([], bad, "checks that did not complete: " + str(bad))

    def test_scan_is_deterministic(self):
        """The same machine state must produce the same findings."""
        first = sorted(f.id for f in self.report.findings)
        second = sorted(f.id for f in _scan().findings)
        self.assertEqual(first, second)

    def test_deep_scan_finds_at_least_as_much(self):
        shallow = {f.id for f in self.report.findings}
        deep = {f.id for f in _scan(deep=True).findings}
        self.assertTrue(shallow <= deep,
                        "a deep scan must not lose findings: "
                        + ", ".join(sorted(shallow - deep)))

    def test_severity_counts_are_sane(self):
        counts = self.report.counts()
        self.assertGreaterEqual(counts.get("critical", 0), 1)
        self.assertGreaterEqual(counts.get("high", 0), 5)
        self.assertGreaterEqual(counts.get("ok", 0), 1)

    def test_findings_are_sorted_by_severity_in_the_report(self):
        ranks = [f.severity.rank for f in self.report.sorted_findings()]
        self.assertEqual(sorted(ranks), ranks)


if __name__ == "__main__":
    unittest.main()
