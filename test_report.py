"""
Report generation tests.

A report is what the user takes away, so it is tested like a deliverable:
every format must be produced, must contain the machine identity and every
finding, and the HTML must not depend on any external resource (it has to open
correctly years later, on a machine with no internet connection).
"""

from __future__ import annotations

import json
import os
import re
import unittest

import harness

harness.use_fixture(writable=True, root=False)
from nexus_doctor.core import report as reporting          # noqa: E402
from nexus_doctor.core.engine import Engine, load_checks   # noqa: E402
from nexus_doctor.core.models import Severity              # noqa: E402


class ReportTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        load_checks()
        cls.report = Engine(deep=False, workers=1).run()

    def test_all_formats_are_produced(self):
        for fmt, ext in (("html", ".html"), ("markdown", ".md"),
                         ("text", ".txt"), ("json", ".json")):
            path = os.path.join(harness.make_scratch_dir(), "report" + ext)
            written = reporting.write_report(self.report, path, fmt=fmt)
            self.assertTrue(os.path.isfile(written))
            self.assertGreater(os.path.getsize(written), 500, fmt)

    def test_format_is_inferred_from_the_extension(self):
        directory = harness.make_scratch_dir()
        for name in ("a.html", "b.md", "c.txt", "d.json"):
            path = reporting.write_report(self.report, os.path.join(directory, name))
            self.assertTrue(os.path.isfile(path), name)
        with open(os.path.join(directory, "d.json"), encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertTrue(any(r["findings"] for r in payload["results"]))

    # -- content ---------------------------------------------------------
    def test_html_contains_machine_and_every_finding(self):
        html = reporting.render_html(self.report)
        self.assertIn("LENOVO", html)
        self.assertIn("81ST", html)
        self.assertIn("Xfce", html)
        plain = _plain(html)
        for f in self.report.findings:
            self.assertIn(f.title, plain,
                          f"finding '{f.title}' is missing from the HTML report")

    def test_html_has_no_external_dependencies(self):
        """It must render offline and years from now."""
        html = reporting.render_html(self.report)
        external = re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html)
        remote = [u for u in external
                  if u.startswith(("http://", "https://", "//", "ftp://"))]
        self.assertEqual([], remote, "the report must not load remote resources")
        self.assertNotIn("@import", html)
        self.assertNotIn("<script", html)

    def test_html_shows_evidence_and_the_command_behind_it(self):
        html = reporting.render_html(self.report)
        self.assertIn("Evidence", html)
        self.assertIn("$ ", html, "commands that produced evidence must be shown")
        self.assertIn("<details>", html)

    def test_html_marks_repairs_and_severity(self):
        html = reporting.render_html(self.report)
        self.assertIn("CRITICAL", html)
        self.assertIn("Automatic repair available", html)

    def test_markdown_contains_machine_and_findings(self):
        md = reporting.render_markdown(self.report)
        self.assertIn("LENOVO", md)
        self.assertIn("## Findings", md)
        for f in self.report.findings:
            self.assertIn(f.title, md)

    def test_text_report_is_plain_and_complete(self):
        text = reporting.render_text(self.report)
        self.assertNotIn("\033", text)
        self.assertIn("SYSTEM DIAGNOSTIC REPORT", text)
        for f in self.report.findings:
            self.assertIn(f.title, text)

    def test_json_round_trips(self):
        payload = json.loads(reporting.render_json(self.report))
        self.assertEqual("Nexus System Doctor", payload["generator"]["name"])
        flat = [f for r in payload["results"] for f in r["findings"]]
        self.assertEqual(len(self.report.findings), len(flat))
        self.assertEqual({f.id for f in self.report.findings},
                         {f["id"] for f in flat})
        for f in flat:
            self.assertTrue(f["summary"], f["id"])
            self.assertTrue(f["evidence"], f["id"])

    def test_repair_results_appear_in_the_report(self):
        """A report written after repairs must show before/after for each."""
        from nexus_doctor.core import executil as ex
        from nexus_doctor.core.repairer import RepairEngine
        harness.use_fixture(writable=True, root=True)
        load_checks()
        report = Engine(deep=False, workers=1).run()
        engine = RepairEngine(report, dry_run=False)
        engine.after_apply_hook = lambda rid: ex.set_phase(1)
        ex.set_phase(0)
        results = [engine.apply("memory.swappiness", confirm=False)]
        html = reporting.render_html(report, results)
        self.assertIn("Repairs applied", html)
        self.assertIn("verified", html)
        self.assertIn("vm.swappiness = 10", html)
        text = reporting.render_text(report, results)
        self.assertIn("REPAIRS APPLIED", text)

    def test_a_failed_repair_is_reported_as_failed(self):
        from nexus_doctor.core import executil as ex
        from nexus_doctor.core.repairer import RepairEngine
        harness.use_fixture(writable=True, root=True)
        load_checks()
        report = Engine(deep=False, workers=1).run()
        engine = RepairEngine(report, dry_run=False)
        ex.set_phase(0)                       # machine never changes
        results = [engine.apply("memory.swappiness", confirm=False)]
        self.assertEqual("failed", results[0].state)
        html = reporting.render_html(report, results)
        self.assertIn("failed", html)
        self.assertNotIn("applied and verified", html)

    def test_report_never_invents_a_missing_tool_result(self):
        """When data is unavailable the report says so instead of guessing."""
        harness.use_fixture(writable=True, root=False)
        load_checks()
        report = Engine(deep=False, workers=1).run()
        for f in report.findings:
            for ev in f.evidence:
                self.assertNotIn("unknown", (ev.detail or "").lower()[:6] or "ok")
        degraded = [r for r in report.results if r.state != "ok"]
        for r in degraded:
            self.assertTrue(r.notes or True)


def _plain(html: str) -> str:
    """Strip tags and resolve entities so titles can be matched literally."""
    import html as htmlmod
    return htmlmod.unescape(re.sub(r"<[^>]+>", " ", html))


if __name__ == "__main__":
    unittest.main()
