"""
Graphical interface tests.

The window is driven headlessly against a virtual X server: it is built, a
scan is run through the real worker thread and event loop, findings are
selected, the repair dialog is opened, and a report is written to disk.  If any
of that raises, the interface would crash on the user's machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import harness

harness.use_fixture(writable=True, root=False)

try:
    import tkinter  # noqa: F401
except ImportError:                                    # pragma: no cover
    tkinter = None


def _display_works() -> bool:
    """True if Tk can actually open a window on the current DISPLAY."""
    if not os.environ.get("DISPLAY"):
        return False
    try:
        probe = tkinter.Tk()
        probe.withdraw()
        probe.destroy()
        return True
    except Exception:
        return False


def _have_display() -> bool:
    return _display_works() or bool(shutil.which("Xvfb"))


@unittest.skipUnless(tkinter, "Tkinter is not installed")
@unittest.skipUnless(_have_display(), "no X display and no Xvfb")
class GuiTests(unittest.TestCase):
    """Drive the real window against the fixture machine."""

    @classmethod
    def setUpClass(cls):
        if not _display_works():
            cls.xvfb = subprocess.Popen(
                ["Xvfb", ":99", "-screen", "0", "1280x900x24"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.environ["DISPLAY"] = ":99"
            time.sleep(1.0)
        else:
            cls.xvfb = None

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "xvfb", None):
            cls.xvfb.terminate()
            cls.xvfb.wait(timeout=10)

    def _pump(self, app, seconds: float = 25.0):
        """Run the Tk event loop until the scan worker finishes."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            app.update()
            if app.report is not None and not (
                    app._worker and app._worker.is_alive()):
                app.update()
                return True
            time.sleep(0.02)
        return False

    def test_window_builds_and_scans(self):
        harness.use_fixture(writable=True, root=False)
        from nexus_doctor.ui.app import NexusDoctorApp
        app = NexusDoctorApp(autoscan=True)
        try:
            self.assertTrue(self._pump(app), "the scan never finished")
            self.assertIsNotNone(app.report)
            self.assertGreater(len(app.report.findings), 10)
            # the findings tree is populated
            groups = app.tree.get_children()
            self.assertGreater(len(groups), 3)
            total = sum(len(app.tree.get_children(g)) for g in groups)
            self.assertGreater(total, 10)
            # status bar and summary reflect the result
            self.assertIn("Scan complete", app.status_var.get())
            self.assertTrue(app.summary_var.get())
        finally:
            app.destroy()

    def test_selecting_a_finding_shows_evidence(self):
        harness.use_fixture(writable=True, root=False)
        from nexus_doctor.ui.app import NexusDoctorApp
        app = NexusDoctorApp(autoscan=True)
        try:
            self.assertTrue(self._pump(app))
            node = None
            for group in app.tree.get_children():
                for child in app.tree.get_children(group):
                    if app._findings.get(child) is not None:
                        node = child
                        break
                if node:
                    break
            self.assertIsNotNone(node)
            app.tree.selection_set(node)
            app.update()
            text = app.detail.get("1.0", "end")
            self.assertIn("Evidence", text)
            self.assertIn("$ ", text, "the command behind the evidence must be shown")
        finally:
            app.destroy()

    def test_repair_dialog_lists_applicable_repairs(self):
        harness.use_fixture(writable=True, root=True)
        from nexus_doctor.ui.app import NexusDoctorApp, RepairDialog
        app = NexusDoctorApp(autoscan=True)
        try:
            self.assertTrue(self._pump(app))
            dialog = RepairDialog(app, app.report)
            try:
                self.assertGreater(len(dialog.plans), 8)
                # selecting the safe ones ticks the low-risk repairs only
                dialog._select_safe()
                ticked = [p for p in dialog.plans
                          if dialog.selected[p.id].get()]
                self.assertTrue(ticked)
                for plan in ticked:
                    self.assertEqual("low", plan.repair.risk.value)
                app.update()
            finally:
                dialog.destroy()
        finally:
            app.destroy()

    def test_reports_can_be_saved_from_the_interface(self):
        harness.use_fixture(writable=True, root=False)
        from nexus_doctor.ui.app import NexusDoctorApp
        app = NexusDoctorApp(autoscan=True)
        try:
            self.assertTrue(self._pump(app))
            directory = tempfile.mkdtemp(prefix="nexus-gui-report-")
            path = os.path.join(directory, "report.html")
            # write_report is what the Save button calls
            from nexus_doctor.core import report as reporting
            written = reporting.write_report(app.report, path)
            self.assertTrue(os.path.isfile(written))
            self.assertGreater(os.path.getsize(written), 2000)
            shutil.rmtree(directory, ignore_errors=True)
        finally:
            app.destroy()

    def test_window_survives_a_repair_run(self):
        """The repair flow must not wedge or crash the event loop."""
        harness.use_fixture(writable=True, root=True)
        from nexus_doctor.core import executil as ex
        from nexus_doctor.core.repairer import RepairEngine
        from nexus_doctor.ui.app import NexusDoctorApp
        app = NexusDoctorApp(autoscan=True)
        try:
            self.assertTrue(self._pump(app))
            engine = RepairEngine(app.report, dry_run=False)
            engine.after_apply_hook = lambda rid: ex.set_phase(1)
            ex.set_phase(0)
            result = engine.apply("memory.swappiness", confirm=False)
            app._on_repairs_complete([result])
            app.update()
            self.assertIn("verified", app.detail.get("1.0", "end").lower())
        finally:
            app.destroy()


if __name__ == "__main__":
    unittest.main()
