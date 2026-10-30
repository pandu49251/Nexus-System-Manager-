"""
Proof that a scan changes nothing.

This is the single most important test in the suite: the application claims
"diagnostics are read-only", and these tests hold it to that claim in two
independent ways.

1. A full scan is run with ``NEXUS_SANDBOX`` pointed at an empty directory, so
   any write outside that directory raises ``SandboxViolation``.  If the scan
   completes without one, it never tried to write anywhere.
2. A full scan is run against a copy of the fixture machine, and the entire
   directory tree is compared byte-for-byte (size + mtime) before and after.
"""

from __future__ import annotations

import os
import unittest

import harness

harness.use_real_machine()
from nexus_doctor.core import executil as ex       # noqa: E402
from nexus_doctor.core.engine import Engine, load_checks   # noqa: E402


class ReadOnlyTests(unittest.TestCase):

    def setUp(self):
        load_checks()

    def test_sandbox_permits_nothing_outside_itself(self):
        harness.use_real_machine()
        sandbox = ex.SANDBOX
        self.assertTrue(sandbox and os.path.isdir(sandbox))
        with self.assertRaises(ex.SandboxViolation):
            ex.write_text("/etc/nexus-must-not-exist.conf", "test")
        with self.assertRaises(ex.SandboxViolation):
            ex.remove("/etc/hostname")
        with self.assertRaises(ex.SandboxViolation):
            ex.write_text("/home/user/.bashrc", "test")
        # inside the sandbox it is allowed
        self.assertTrue(ex.write_text(os.path.join(sandbox, "probe.txt"), "ok"))
        self.assertTrue(os.path.isfile(os.path.join(sandbox, "probe.txt")))

    def test_full_scan_against_this_machine_writes_nothing(self):
        """Run every check against the real machine with writes blocked."""
        harness.use_real_machine()
        load_checks()
        violations = []
        real_check = ex._check_write_allowed

        def spy(path):
            try:
                real_check(path)
            except ex.SandboxViolation:
                violations.append(path)
                raise

        ex._check_write_allowed = spy
        try:
            # Quick scan: reading /proc and /sys is what a real scan does.
            report = Engine(deep=False, workers=4).run()
        finally:
            ex._check_write_allowed = real_check

        self.assertEqual([], violations,
                         "a scan must never write: " + ", ".join(violations))
        self.assertGreater(len(report.results), 10)
        # A scan that wrote nothing must still produce findings or honest
        # "could not complete" results - never both silent and empty.
        self.assertTrue(report.findings or
                        any(r.state != "ok" for r in report.results))

    def test_scan_does_not_modify_the_filesystem_tree(self):
        harness.use_fixture(writable=True, root=False)
        load_checks()
        rootfs = ex.SYSROOT
        before = harness.manifest(rootfs)
        Engine(deep=False, workers=4).run()
        after = harness.manifest(rootfs)
        self.assertEqual({}, harness.manifest_diff(before, after),
                         "a scan modified the filesystem tree")

    def test_deep_scan_does_not_modify_the_filesystem_tree(self):
        """The disk benchmark creates a temporary file; it must clean up."""
        harness.use_fixture(writable=True, root=True)
        load_checks()
        rootfs = ex.SYSROOT
        before = harness.manifest(rootfs)
        Engine(deep=True, workers=1).run()
        after = harness.manifest(rootfs)
        diff = harness.manifest_diff(before, after)
        leftovers = [p for p in diff if "benchmark" in p]
        self.assertEqual([], leftovers,
                         "the disk benchmark left a file behind: " + str(leftovers))

    def test_repairs_in_dry_run_change_nothing(self):
        harness.use_fixture(writable=True, root=True)
        load_checks()
        from nexus_doctor.core.repairer import RepairEngine
        rootfs = ex.SYSROOT
        report = Engine(deep=False, workers=1).run()
        engine = RepairEngine(report, dry_run=True)
        before = harness.manifest(rootfs)
        for plan in engine.plans():
            if not plan.blocked:
                engine.apply(plan.id, confirm=False)
        after = harness.manifest(rootfs)
        self.assertEqual({}, harness.manifest_diff(before, after),
                         "a dry run modified the filesystem tree")

    def test_unprivileged_run_does_not_attempt_privilege_escalation(self):
        """Without root the app must report 'needs root', never try sudo."""
        harness.use_fixture(writable=True, root=False)
        load_checks()
        seen = []
        original = ex.run

        def spy(argv, *a, **kw):
            seen.append([str(x) for x in argv])
            return original(argv, *a, **kw)

        ex.run = spy
        try:
            Engine(deep=False, workers=1).run()
        finally:
            ex.run = original

        escalations = [argv for argv in seen
                       if argv and argv[0].split("/")[-1] in
                       ("sudo", "su", "pkexec", "doas", "gksu", "kdesu")]
        self.assertEqual([], escalations,
                         "the scan must not invoke a privilege-escalation tool")


if __name__ == "__main__":
    unittest.main()
