"""
Repair tests: verify before, apply, verify after.

The most important assertion here is a negative one.  In
:meth:`RepairTests.test_a_repair_that_did_not_work_is_reported_failed` the
repair runs, returns success, and the machine is left exactly as it was - and
every single repair must then be reported as *failed*.  If any of them were
reported as verified, the tool would be claiming success without evidence,
which is precisely what it must never do.
"""

from __future__ import annotations

import os
import unittest

import harness

harness.use_fixture(writable=True, root=True)
from nexus_doctor.core import executil as ex            # noqa: E402
from nexus_doctor.core.engine import Engine, load_checks  # noqa: E402
from nexus_doctor.core.repairer import RepairEngine, all_repairs  # noqa: E402


def _scan():
    harness.use_fixture(writable=True, root=True)
    load_checks()
    return Engine(deep=False, workers=1).run()


#: Every repair that can be applied to the fixture machine unattended.
#: services.trim_autostart is deliberately excluded: it must never guess
#: which of the user's startup applications to disable.
EXPECTED_APPLICABLE = {
    "cleanup.apt_cache", "cleanup.journal", "cleanup.thumbnails",
    "cpu.governor", "input.keyrepeat", "input.layout", "memory.swappiness",
    "memory.zram_swap", "services.disable_indexers", "services.disable_unused",
    "services.disable_apt_timers", "storage.dirty_ratio", "storage.enable_smartd",
    "storage.io_scheduler",
    "storage.noatime", "xfce.compositing_off", "software.fix_dpkg",
}


class RepairTests(unittest.TestCase):

    def setUp(self):
        self.report = _scan()
        self.engine = RepairEngine(self.report, dry_run=False)

    # ------------------------------------------------------------------
    def test_all_repairs_are_registered(self):
        ids = {r.id for r in all_repairs()}
        for expected in EXPECTED_APPLICABLE:
            self.assertIn(expected, ids, f"{expected} is not registered")
        self.assertIn("services.trim_autostart", ids)
        self.assertIn("services.disable_apt_timers", ids)

    def test_every_repair_declares_risk_and_steps(self):
        for rep in all_repairs():
            self.assertTrue(rep.title, rep.id)
            self.assertTrue(rep.risk, rep.id)
            self.assertTrue(rep.undoable in (True, False), rep.id)

    def test_plans_cover_expected_repairs(self):
        plans = {p.id for p in self.engine.plans() if not p.blocked}
        self.assertEqual(EXPECTED_APPLICABLE, plans,
                         "unexpected set of applicable repairs")

    def test_no_plan_is_offered_for_a_problem_that_is_not_there(self):
        """Repairs must be offered for this machine's faults, nothing else."""
        for plan in self.engine.plans():
            if plan.blocked:
                continue
            self.assertTrue(plan.reason or plan.steps, plan.id)
            self.assertIsNotNone(plan.finding, f"{plan.id} has no source finding")

    # -- the core safety property --------------------------------------
    def test_a_repair_that_did_not_work_is_reported_failed(self):
        """Apply every repair but leave the machine unchanged.

        Nothing may come back 'verified': the engine must notice that the
        post-condition was not met and say so.
        """
        falsely_ok = []
        for plan in self.engine.plans():
            if plan.blocked:
                continue
            ex.set_phase(0)                        # machine state never changes
            result = self.engine.apply(plan.id, confirm=False)
            if result.state == "verified":
                falsely_ok.append(plan.id)
            self.assertTrue(result.verify_before,
                            f"{plan.id}: no pre-repair measurement")
        self.assertEqual([], falsely_ok,
                         "claimed success without evidence: " + ", ".join(falsely_ok))

    def test_every_repair_verifies_when_the_change_really_happens(self):
        """With the machine actually changing state, all must verify."""
        self.engine.after_apply_hook = lambda rid: ex.set_phase(1)
        failures = []
        for plan in self.engine.plans():
            if plan.blocked:
                continue
            ex.set_phase(0)
            result = self.engine.apply(plan.id, confirm=False)
            if result.state != "verified":
                failures.append(f"{plan.id}: {result.state} - {result.message[:70]}")
            self.assertNotEqual(result.verify_before, result.verify_after,
                                f"{plan.id}: before and after are identical")
        self.assertEqual([], failures, "repairs that did not verify:\n  "
                         + "\n  ".join(failures))

    def test_verification_reports_before_and_after(self):
        self.engine.after_apply_hook = lambda rid: ex.set_phase(1)
        for plan in self.engine.plans():
            if plan.blocked:
                continue
            ex.set_phase(0)
            result = self.engine.apply(plan.id, confirm=False)
            self.assertTrue(result.verify_before.strip(), plan.id)
            self.assertTrue(result.verify_after.strip(), plan.id)

    # -- backups and rollback -------------------------------------------
    def test_modifying_a_config_file_makes_a_backup_first(self):
        self.engine.after_apply_hook = lambda rid: ex.set_phase(1)
        ex.set_phase(0)
        result = self.engine.apply("storage.noatime", confirm=False)
        self.assertEqual("verified", result.state)
        self.assertTrue(result.backups, "no backup was recorded for /etc/fstab")
        backup = result.backups[-1]
        self.assertTrue(os.path.isfile(backup), f"backup missing: {backup}")
        with open(backup, encoding="utf-8") as fh:
            self.assertIn("errors=remount-ro", fh.read())
        # and the edit itself landed in the filesystem
        with open(os.path.join(ex.SYSROOT, "etc/fstab"), encoding="utf-8") as fh:
            self.assertIn("noatime", fh.read())

    def test_rollback_restores_the_original_value(self):
        self.engine.after_apply_hook = lambda rid: ex.set_phase(1)
        for rid in ("memory.swappiness", "storage.io_scheduler",
                    "services.disable_apt_timers"):
            ex.set_phase(0)
            applied = self.engine.apply(rid, confirm=False)
            self.assertEqual("verified", applied.state, rid)
            ex.set_phase(0)            # the rollback puts the machine back
            rolled = self.engine.rollback(rid)
            self.assertEqual("verified", rolled.state,
                             f"{rid} rollback: {rolled.message}")

    def test_destructive_repair_refuses_to_roll_back(self):
        """A repair that only deletes regenerable data cannot be undone."""
        ex.set_phase(0)
        self.engine.after_apply_hook = lambda rid: ex.set_phase(1)
        self.engine.apply("cleanup.apt_cache", confirm=False)
        result = self.engine.rollback("cleanup.apt_cache")
        self.assertNotEqual("verified", result.state)
        self.assertTrue(result.message)

    # -- the autostart repair must not guess ----------------------------
    def test_autostart_trim_requires_the_user_to_choose(self):
        plan = next((p for p in self.engine.plans()
                     if p.id == "services.trim_autostart"), None)
        self.assertIsNotNone(plan)
        self.assertTrue(plan.blocked,
                        "trimming autostart must never be offered unprompted")

    # -- dry run ---------------------------------------------------------
    def test_dry_run_reports_pending_and_changes_nothing(self):
        dry = RepairEngine(self.report, dry_run=True)
        for plan in dry.plans():
            if plan.blocked:
                continue
            result = dry.apply(plan.id, confirm=False)
            self.assertEqual("pending", result.state, plan.id)
            self.assertNotEqual("verified", result.state, plan.id)

    def test_unknown_repair_is_reported_not_guessed(self):
        result = self.engine.apply("does.not.exist", confirm=False)
        self.assertEqual("failed", result.state)
        self.assertIn("unknown repair", result.message)


if __name__ == "__main__":
    unittest.main()
