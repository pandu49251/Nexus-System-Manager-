"""
nexus_doctor.ui.app
===================

The graphical interface: a single Tkinter window.

Design constraints that shaped this code:

* **Responsive during scanning.**  Scans run on a worker thread and report
  progress through a queue; the UI polls that queue 20 times a second and stops
  polling when idle, so an idle window costs essentially nothing.
* **No external assets.**  No icon files, no fonts, no stylesheets - everything
  is drawn with Tk primitives, so it cannot break on a minimal install.
* **Evidence first.**  Selecting a finding shows the summary, the root cause,
  the recommended actions and - critically - the exact commands behind every
  claim, so the user can verify rather than trust.
* **Repairs are opt-in.**  The repair dialog shows the risk, what will be done,
  whether administrator rights are needed and what can be undone, and nothing
  is applied until the user confirms.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Sequence

from ..core import privileges, report as reporting
from ..core.engine import Engine, load_checks
from ..core.models import (CATEGORY_LABELS, Category, Finding, RepairResult,
                           ScanReport, Severity)
from ..core.repairer import RepairEngine, RepairPlan
from ..version import APP_NAME, COPYRIGHT, LICENSE, __version__
from . import theme

log = logging.getLogger("nexus.ui")

POLL_MS = 50


class NexusDoctorApp(tk.Tk):
    """Main application window."""

    def __init__(self, deep: bool = False, autoscan: bool = True):
        super().__init__()
        self.title(f"{APP_NAME} {__version__}")
        self.geometry("1080x700")
        self.minsize(880, 560)
        theme.setup(self)

        self.report: Optional[ScanReport] = None
        self.repair_results: List[RepairResult] = []
        self._queue: "queue.Queue" = queue.Queue()
        self._worker: Optional[threading.Thread] = None
        self._polling = False
        self._findings: Dict[str, Finding] = {}
        self._pending_deep = deep

        self._build_menu()
        self._build_header()
        self._build_body()
        self._build_status()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        if autoscan:
            self.after(200, lambda: self.start_scan(deep=deep))

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save report as HTML...",
                              command=lambda: self.save_report("html"))
        file_menu.add_command(label="Save report as Markdown...",
                              command=lambda: self.save_report("markdown"))
        file_menu.add_command(label="Save report as plain text...",
                              command=lambda: self.save_report("text"))
        file_menu.add_command(label="Export data as JSON...",
                              command=lambda: self.save_report("json"))
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        scan_menu = tk.Menu(menubar, tearoff=0)
        scan_menu.add_command(label="Quick scan", command=lambda: self.start_scan(False))
        scan_menu.add_command(label="Deep scan (measures disk speed)",
                              command=lambda: self.start_scan(True))
        menubar.add_cascade(label="Scan", menu=scan_menu)

        repair_menu = tk.Menu(menubar, tearoff=0)
        repair_menu.add_command(label="Review and apply repairs...",
                                command=self.open_repair_dialog)
        repair_menu.add_command(label="Roll back a repair...",
                                command=self.open_rollback_dialog)
        menubar.add_cascade(label="Repair", menu=repair_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="How repairs are kept safe", command=self.show_safety)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    def _build_header(self) -> None:
        header = ttk.Frame(self, style="Header.TFrame", padding=(14, 10))
        header.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(header, text=f"{APP_NAME}", style="Header.TLabel").pack(anchor="w")
        self.header_sub = ttk.Label(header, text="Starting...", style="HeaderSub.TLabel")
        self.header_sub.pack(anchor="w")

        bar = ttk.Frame(self, padding=(10, 6))
        bar.pack(side=tk.TOP, fill=tk.X)
        self.btn_quick = ttk.Button(bar, text="Quick scan",
                                    command=lambda: self.start_scan(False))
        self.btn_quick.pack(side=tk.LEFT)
        self.btn_deep = ttk.Button(bar, text="Deep scan",
                                   command=lambda: self.start_scan(True))
        self.btn_deep.pack(side=tk.LEFT, padx=6)
        self.btn_repair = ttk.Button(bar, text="Review repairs...",
                                     command=self.open_repair_dialog, state=tk.DISABLED)
        self.btn_repair.pack(side=tk.LEFT)
        ttk.Button(bar, text="Save report...",
                   command=lambda: self.save_report("html")).pack(side=tk.LEFT, padx=6)

        self.summary_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.summary_var,
                  style="Muted.TLabel").pack(side=tk.RIGHT)
        if not privileges.is_root():
            ttk.Label(bar, text="  (running without administrator rights)",
                      style="Muted.TLabel").pack(side=tk.RIGHT)

    def _build_body(self) -> None:
        body = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))

        left = ttk.Frame(body, width=430)
        body.add(left, weight=2)
        columns = ("sev", "issue", "where")
        self.tree = ttk.Treeview(left, columns=columns, show="tree headings",
                                 selectmode="browse")
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=0, stretch=False)
        self.tree.heading("sev", text="")
        self.tree.column("sev", width=26, anchor="center", stretch=False)
        self.tree.heading("issue", text="Finding")
        self.tree.column("issue", width=300, anchor="w")
        self.tree.heading("where", text="Area")
        self.tree.column("where", width=110, anchor="w")
        for sev in ("critical", "high", "medium", "low", "info", "ok"):
            self.tree.tag_configure(sev, foreground=theme.COLOURS[sev])
        self.tree.tag_configure("group", foreground=theme.MUTED)
        scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        right = ttk.Frame(body)
        body.add(right, weight=3)
        self.detail = tk.Text(right, wrap=tk.WORD, padx=12, pady=10,
                              spacing1=2, spacing3=4)
        dscroll = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.detail.yview)
        self.detail.configure(yscrollcommand=dscroll.set)
        dscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._configure_text_tags()
        self._show_welcome()

    def _configure_text_tags(self) -> None:
        self.detail.tag_configure("h1", font=("Sans", 13, "bold"), spacing3=8,
                                  foreground="#123a5e")
        self.detail.tag_configure("h2", font=("Sans", 10, "bold"), spacing1=10,
                                  foreground="#444")
        self.detail.tag_configure("body", spacing1=2, lmargin1=6, lmargin2=6)
        self.detail.tag_configure("mono", font=("DejaVu Sans Mono", 9),
                                  background="#f0f2f4", lmargin1=18, lmargin2=18,
                                  spacing1=1)
        self.detail.tag_configure("cmd", font=("DejaVu Sans Mono", 9, "bold"),
                                  foreground="#1d6fa5", lmargin1=18, lmargin2=18)
        self.detail.tag_configure("bullet", lmargin1=18, lmargin2=30, spacing1=1)
        self.detail.tag_configure("muted", foreground=theme.MUTED)
        for sev, colour in theme.COLOURS.items():
            self.detail.tag_configure(f"sev_{sev}", foreground=colour)

    def _build_status(self) -> None:
        bar = ttk.Frame(self, padding=(10, 4))
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var,
                  style="Muted.TLabel").pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(bar, mode="determinate", length=180)
        self.progress.pack(side=tk.RIGHT)

    def _show_welcome(self) -> None:
        self._set_text(
            ("h1", f"{APP_NAME} {__version__}\n"),
            ("body", "A diagnostic tool that measures your system, explains what it "
                     "finds, and repairs only what it can verify.\n\n"),
            ("h2", "What happens when you scan\n"),
            ("body", "The scan is strictly read-only: it reads /proc and /sys, and runs "
                     "standard diagnostic tools such as smartctl, sensors and journalctl. "
                     "It never installs, deletes or changes anything.\n\n"),
            ("h2", "About repairs\n"),
            ("body", "Repairs are never applied automatically. Each one shows you the "
                     "risk, exactly what it will do, and whether it needs your "
                     "administrator password. Afterwards the app re-measures the system "
                     "and only reports success if the change actually took effect. "
                     "Everything reversible can be undone from the Repair menu.\n\n"),
            ("h2", "Hint\n"),
            ("body", "For the most complete picture, run a deep scan. It additionally "
                     "measures how fast your disk really is, which is often the "
                     "decisive number on an older laptop.\n"))

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def start_scan(self, deep: bool = False) -> None:
        if self._worker and self._worker.is_alive():
            messagebox.showinfo("Scan in progress", "A scan is already running.")
            return
        load_checks()
        self.btn_quick.configure(state=tk.DISABLED)
        self.btn_deep.configure(state=tk.DISABLED)
        self.btn_repair.configure(state=tk.DISABLED)
        self.progress["value"] = 0
        self.status_var.set("Scanning...")
        self.summary_var.set("")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._findings.clear()
        self._set_text(("h1", "Scanning..."),
                       ("body", "\nReading system state. This is read-only and "
                                "changes nothing."))

        self._worker = threading.Thread(
            target=self._scan_worker, args=(deep,), daemon=True)
        self._worker.start()
        self._start_polling()

    def _scan_worker(self, deep: bool) -> None:
        try:
            engine = Engine(deep=deep)
            report = engine.run(progress=lambda cid, title, done, total:
                                self._queue.put(("progress", (title, done, total))))
            self._queue.put(("done", report))
        except Exception as exc:
            log.exception("scan failed")
            self._queue.put(("error", f"{type(exc).__name__}: {exc}"))

    def _start_polling(self) -> None:
        if self._polling or not self.winfo_exists():
            return
        self._polling = True
        self._poll()

    def _poll(self) -> None:
        if not self.winfo_exists():
            self._polling = False
            return
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    title, done, total = payload
                    self.progress["maximum"] = max(1, total)
                    self.progress["value"] = done
                    self.status_var.set(f"Scanning: {title} ({done}/{total})")
                elif kind == "done":
                    self._on_scan_complete(payload)
                elif kind == "error":
                    self.status_var.set(f"Scan failed: {payload}")
                    messagebox.showerror("Scan failed", str(payload))
                    self._enable_buttons()
                elif kind == "repair_done":
                    self._on_repairs_complete(payload)
        except queue.Empty:
            pass
        if self._worker and self._worker.is_alive():
            self.after(POLL_MS, self._poll)
        else:
            self._polling = False

    def _enable_buttons(self) -> None:
        self.btn_quick.configure(state=tk.NORMAL)
        self.btn_deep.configure(state=tk.NORMAL)
        if self.report is not None:
            self.btn_repair.configure(state=tk.NORMAL)

    def _on_scan_complete(self, report: ScanReport) -> None:
        self.report = report
        self.progress["value"] = self.progress["maximum"]
        counts = report.counts()
        self.summary_var.set("  ".join(f"{s.upper()} {counts.get(s, 0)}"
                                       for s in ("critical", "high", "medium",
                                                 "low", "info", "ok")))
        machine = report.machine.describe() or report.hostname or "this machine"
        self.header_sub.configure(
            text=f"{machine}  |  {report.distro or 'Linux'}  |  "
                 f"{report.desktop or ''}  |  kernel {report.kernel}  |  "
                 f"{report.mem_total_mb} MB RAM  |  disk {report.root_disk or '?'}")
        self.status_var.set(
            f"Scan complete in {report.finished - report.started:.1f}s "
            f"({'deep' if report.deep else 'quick'})")
        self._populate_tree(report)
        self._enable_buttons()

        worst = next((f for f in sorted(report.findings, key=lambda x: x.severity.rank)
                      if f.severity.rank <= Severity.HIGH.rank), None)
        if worst:
            self._show_finding(worst)
            for item in self.tree.get_children():
                for child in self.tree.get_children(item):
                    if self.tree.item(child, "values") and \
                            self._findings.get(child) is worst:
                        self.tree.selection_set(child)
                        self.tree.see(child)
                        break
        else:
            self._set_text(("h1", "No serious problems found"),
                           ("body", "\n" + self._summary_paragraph(report)))

    def _populate_tree(self, report: ScanReport) -> None:
        findings = report.sorted_findings()
        groups: Dict[str, List[Finding]] = {}
        for f in findings:
            groups.setdefault(CATEGORY_LABELS.get(f.category.value, f.category.value),
                              []).append(f)
        order = sorted(groups.items(),
                       key=lambda kv: min(x.severity.rank for x in kv[1]))
        for label, items in order:
            worst = min((x.severity for x in items), key=lambda s: s.rank)
            parent = self.tree.insert(
                "", tk.END, text=label,
                values=("", f"{label} ({len(items)})", ""),
                tags=("group",), open=True)
            for f in items:
                node = self.tree.insert(
                    parent, tk.END,
                    values=(theme.SYMBOLS.get(f.severity.value, ""),
                            f.title, label),
                    tags=(f.severity.value,))
                self._findings[node] = f
        for item in self.tree.get_children():
            self.tree.item(item, open=True)

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        finding = self._findings.get(sel[0])
        if finding:
            self._show_finding(finding)

    # ------------------------------------------------------------------
    # Detail rendering
    # ------------------------------------------------------------------

    def _set_text(self, *blocks) -> None:
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        for block in blocks:
            tag, text = block
            self.detail.insert(tk.END, text, tag)
        self.detail.configure(state=tk.DISABLED)
        self.detail.see("1.0")

    def _show_finding(self, f: Finding) -> None:
        blocks = [
            ("h1", f.title + "\n"),
            (f"sev_{f.severity.value}", f"{f.severity.value.upper()}"),
            ("muted", f"    in {CATEGORY_LABELS.get(f.category.value, f.category.value)}"
                      f"    confidence: {f.confidence.value}"
                      f"    id: {f.id}\n\n"),
        ]
        if f.summary:
            blocks.append(("body", f.summary + "\n\n"))
        if f.root_cause:
            blocks.append(("h2", "Likely root cause\n"))
            blocks.append(("body", f.root_cause + "\n\n"))
        if f.impact:
            blocks.append(("h2", "What you will notice\n"))
            blocks.append(("body", f.impact + "\n\n"))
        if f.recommendations:
            blocks.append(("h2", "Recommended actions\n"))
            for rec in f.recommendations:
                blocks.append(("bullet", f"•  {rec}\n"))
            blocks.append(("body", "\n"))
        if f.repair_ids:
            blocks.append(("h2", "Automatic repair available\n"))
            blocks.append(("body", ", ".join(f.repair_ids) +
                           "\nUse the 'Review repairs' button to see exactly what it "
                           "would do before allowing it.\n\n"))
        if f.evidence:
            blocks.append(("h2", f"Evidence ({len(f.evidence)})\n"))
            for ev in f.evidence:
                blocks.append(("body", f"{ev.source}\n"))
                blocks.append(("muted", f"    {ev.detail}\n"))
                if ev.command:
                    blocks.append(("cmd", f"    $ {ev.command}\n"))
                if ev.raw and ev.raw.strip():
                    raw = ev.raw.strip()
                    if len(raw) > 1200:
                        raw = raw[:1200] + "\n... (truncated)"
                    blocks.append(("mono", "\n".join("      " + line
                                                     for line in raw.splitlines()) + "\n"))
                blocks.append(("body", "\n"))
        if f.needs_root and not privileges.is_root():
            blocks.append(("muted", "Note: part of this evidence requires administrator "
                                    "rights. Run 'sudo nexus-doctor --cli --scan' for the "
                                    "complete picture.\n"))
        if f.needs_network:
            blocks.append(("muted", "Note: acting on this requires an internet "
                                    "connection (to install a package).\n"))
        self._set_text(*blocks)

    def _summary_paragraph(self, report: ScanReport) -> str:
        counts = report.counts()
        return (f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
                f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low and "
                f"{counts.get('ok', 0)} passing checks. "
                f"Select a finding on the left for details and evidence.")

    # ------------------------------------------------------------------
    # Repairs
    # ------------------------------------------------------------------

    def open_repair_dialog(self) -> None:
        if self.report is None:
            messagebox.showinfo("No scan yet", "Run a scan first.")
            return
        RepairDialog(self, self.report)

    def open_rollback_dialog(self) -> None:
        if self.report is None:
            messagebox.showinfo("No scan yet", "Run a scan first.")
            return
        RollbackDialog(self, self.report)

    def apply_repairs(self, plans: Sequence[RepairPlan]) -> None:
        """Apply the chosen repairs on a worker thread."""
        self.status_var.set("Applying repairs...")
        self.progress["value"] = 0
        self.progress["maximum"] = max(1, len(plans))

        def worker():
            engine = RepairEngine(self.report, dry_run=False)
            results = []
            for i, plan in enumerate(plans):
                result = engine.apply(plan.id, confirm=False)
                results.append(result)
                self._queue.put(("repair_progress", (i + 1, len(plans), result)))
            self._queue.put(("repair_done", results))

        threading.Thread(target=worker, daemon=True).start()
        self._start_polling()
        self.after(POLL_MS, self._poll)

    def _on_repairs_complete(self, results: List[RepairResult]) -> None:
        self.repair_results.extend(results)
        verified = sum(1 for r in results if r.state == "verified")
        self.status_var.set(f"{verified} of {len(results)} repairs verified")
        self.progress["value"] = self.progress["maximum"]
        lines = []
        lines.append(("h1", "Repair results\n"))
        lines.append(("body",
                      "Each repair was measured before and after. A repair is reported "
                      "as successful only if the second measurement shows the intended "
                      "state.\n\n"))
        for r in results:
            colour = "sev_ok" if r.state == "verified" else "sev_critical"
            lines.append((colour, f"[{r.state.upper():8s}] "))
            lines.append(("body", f"{r.title}\n"))
            if r.verify_before:
                lines.append(("muted", f"          before: {r.verify_before}\n"))
            if r.verify_after:
                lines.append(("muted", f"          after : {r.verify_after}\n"))
            if r.state != "verified":
                lines.append(("body", f"          {r.message}\n"))
            if r.backups:
                lines.append(("muted", f"          backup: {r.backups[-1]}\n"))
            lines.append(("body", "\n"))
        lines.append(("muted", "Re-run a scan to see the updated findings. Undo any "
                               "reversible repair from Repair > Roll back a repair.\n"))
        self._set_text(*lines)
        self._enable_buttons()

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def save_report(self, fmt: str) -> None:
        if self.report is None:
            messagebox.showinfo("No scan yet", "Run a scan first.")
            return
        exts = {"html": (".html", "HTML report"),
                "markdown": (".md", "Markdown report"),
                "text": (".txt", "Plain text report"),
                "json": (".json", "JSON data")}
        ext, desc = exts[fmt]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=ext,
            initialfile=f"nexus-report-{stamp}{ext}",
            filetypes=[(desc, f"*{ext}"), ("All files", "*.*")],
            title="Save diagnostic report")
        if not path:
            return
        try:
            reporting.write_report(self.report, path, fmt=fmt,
                                   repairs=self.repair_results)
        except OSError as exc:
            messagebox.showerror("Could not save", str(exc))
            return
        self.status_var.set(f"Report saved to {path}")
        if messagebox.askyesno("Report saved",
                               f"Saved to:\n{path}\n\nOpen it now?"):
            try:
                webbrowser.open(f"file://{path}")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Dialogs
    # ------------------------------------------------------------------

    def show_about(self) -> None:
        messagebox.showinfo(
            "About " + APP_NAME,
            f"{APP_NAME} {__version__}\n\n"
            f"A diagnostic and repair tool for Linux desktops.\n\n"
            f"{COPYRIGHT}\nLicence: {LICENSE}\n\n"
            f"Diagnostics are read-only. Repairs are opt-in, backed up where they "
            f"modify configuration, and verified afterwards.")

    def show_safety(self) -> None:
        SafetyDialog(self)

    def _on_close(self) -> None:
        if self._worker and self._worker.is_alive():
            if not messagebox.askokcancel("Scan running",
                                          "A scan is still running. Quit anyway?"):
                return
        # Cancel queued callbacks so nothing touches Tk after the window dies.
        self._polling = False
        try:
            for after_id in str(self.tk.eval("after info")).split():
                self.after_cancel(after_id)
        except Exception:
            pass
        self.destroy()


# --------------------------------------------------------------------------
# Repair dialog
# --------------------------------------------------------------------------


class RepairDialog(tk.Toplevel):
    """Shows every applicable repair with its risk and exact steps."""

    def __init__(self, master: NexusDoctorApp, report: ScanReport):
        super().__init__(master)
        self.master_app = master
        self.report = report
        self.engine = RepairEngine(report, dry_run=True)
        self.title("Review repairs")
        self.geometry("760x560")
        self.transient(master)
        self.grab_set()
        theme.setup(self)

        self.plans = [p for p in self.engine.plans() if not p.blocked]
        self.blocked = [p for p in self.engine.plans() if p.blocked]
        self.selected: Dict[str, tk.BooleanVar] = {}
        self._build()

    def _build(self) -> None:
        head = ttk.Frame(self, padding=(12, 10))
        head.pack(fill=tk.X)
        ttk.Label(head, text="Review repairs", font=("Sans", 12, "bold")).pack(anchor="w")
        ttk.Label(head,
                  text="Nothing is applied until you press 'Apply selected'. "
                       "Every repair is re-measured afterwards.",
                  style="Muted.TLabel").pack(anchor="w")

        body = ttk.Frame(self, padding=(12, 0))
        body.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(body, highlightthickness=0, background=theme.BG)
        scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=canvas.yview)
        self.inner = ttk.Frame(canvas)
        self.inner.bind("<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        if not self.plans and not self.blocked:
            ttk.Label(self.inner, text="No repairs are applicable to this machine.",
                      padding=10).pack(anchor="w")
        for plan in self.plans:
            self._add_plan(plan, enabled=True)
        for plan in self.blocked:
            self._add_plan(plan, enabled=False)

        foot = ttk.Frame(self, padding=(12, 10))
        foot.pack(fill=tk.X)
        ttk.Button(foot, text="Select all safe (low risk)",
                   command=self._select_safe).pack(side=tk.LEFT)
        ttk.Button(foot, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=6)
        ttk.Button(foot, text="Cancel", command=self.destroy).pack(side=tk.RIGHT)
        ttk.Button(foot, text="Apply selected", style="Accent.TButton",
                   command=self._apply).pack(side=tk.RIGHT, padx=6)

    def _risk_colour(self, risk: str) -> str:
        return {"low": theme.COLOURS["ok"], "medium": theme.COLOURS["medium"],
                "high": theme.COLOURS["critical"],
                "manual": theme.MUTED}.get(risk, theme.MUTED)

    def _add_plan(self, plan: RepairPlan, enabled: bool) -> None:
        card = ttk.Frame(self.inner, style="Card.TFrame", padding=10)
        card.pack(fill=tk.X, pady=5)
        top = ttk.Frame(card, style="Panel.TFrame")
        top.pack(fill=tk.X)
        var = tk.BooleanVar(value=False)
        self.selected[plan.id] = var
        cb = ttk.Checkbutton(top, variable=var,
                             state=tk.NORMAL if enabled else tk.DISABLED)
        cb.pack(side=tk.LEFT)
        ttk.Label(top, text=plan.repair.title, font=("Sans", 10, "bold"),
                  background=theme.PANEL, wraplength=560,
                  justify=tk.LEFT).pack(side=tk.LEFT, anchor="w")

        badges = ttk.Frame(card, style="Panel.TFrame")
        badges.pack(fill=tk.X, pady=(4, 0))
        risk_lbl = tk.Label(badges, text=f"RISK: {plan.risk.value.upper()}",
                            fg="white", bg=self._risk_colour(plan.risk.value),
                            font=("Sans", 8, "bold"), padx=6, pady=1)
        risk_lbl.pack(side=tk.LEFT)
        for text in ([("needs administrator", plan.repair.requires_root) if False else
                      ("needs administrator password", plan.repair.requires_root),
                      ("needs the graphical session", plan.repair.requires_gui),
                      ("needs internet", plan.repair.requires_network),
                      ("reboot needed", plan.repair.reboot_required)]):
            if text[1]:
                tk.Label(badges, text=text[0], fg=theme.MUTED, bg=theme.PANEL,
                         font=("Sans", 8), padx=4).pack(side=tk.LEFT)

        why = tk.Label(card, text=plan.blocked or plan.reason,
                       bg=theme.PANEL, fg=theme.FG if enabled else theme.MUTED,
                       wraplength=640, justify=tk.LEFT, anchor="w",
                       font=("Sans", 9))
        why.pack(fill=tk.X, pady=(4, 0))

        steps = tk.Label(card, bg=theme.PANEL, fg=theme.MUTED,
                         text="\n".join("   - " + s for s in plan.steps),
                         wraplength=640, justify=tk.LEFT, anchor="w",
                         font=("Sans", 8))
        steps.pack(fill=tk.X, pady=(2, 0))
        if plan.finding is not None:
            tk.Label(card, bg=theme.PANEL, fg=theme.MUTED,
                     text=f"addresses: {plan.finding.title}",
                     wraplength=640, justify=tk.LEFT, anchor="w",
                     font=("Sans", 8, "italic")).pack(fill=tk.X, pady=(2, 0))

    def _select_safe(self) -> None:
        for plan in self.plans:
            self.selected[plan.id].set(plan.repair.risk.value == "low")

    def _clear(self) -> None:
        for var in self.selected.values():
            var.set(False)

    def _apply(self) -> None:
        chosen = [p for p in self.plans if self.selected[p.id].get()]
        if not chosen:
            messagebox.showinfo("Nothing selected",
                                "Select at least one repair, or press Cancel.")
            return
        risky = [p for p in chosen if p.repair.risk.value in ("high", "medium")]
        lines = ["The following repairs will be applied:", ""]
        for p in chosen:
            lines.append(f"  [{p.repair.risk.value.upper()}] {p.repair.title}")
        lines.append("")
        if risky:
            lines.append("The following change system configuration and will be "
                         "backed up first:")
            for p in risky:
                lines.append(f"  - {p.repair.title}")
            lines.append("")
        lines.append("Each one is checked again afterwards; if it did not take "
                     "effect it will be reported as failed.")
        if not messagebox.askyesno("Confirm repairs", "\n".join(lines)):
            return
        self.destroy()
        self.master_app.apply_repairs(chosen)


# --------------------------------------------------------------------------
# Rollback dialog
# --------------------------------------------------------------------------


class RollbackDialog(tk.Toplevel):
    """Undo a previously applied repair."""

    def __init__(self, master: NexusDoctorApp, report: ScanReport):
        super().__init__(master)
        self.master_app = master
        self.report = report
        self.engine = RepairEngine(report, dry_run=False)
        self.title("Roll back a repair")
        self.geometry("620x420")
        self.transient(master)
        self.grab_set()
        theme.setup(self)
        self._build()

    def _build(self) -> None:
        ttk.Label(self, text="Roll back a repair",
                  font=("Sans", 12, "bold"), padding=(12, 10)).pack(anchor="w")
        ttk.Label(self, text="Select a repair to undo. Repairs that only delete "
                             "regenerable caches cannot be undone.",
                  style="Muted.TLabel", padding=(12, 0)).pack(anchor="w")

        frame = ttk.Frame(self, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)
        self.listbox = tk.Listbox(frame, font=("Sans", 9))
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.listbox.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.configure(yscrollcommand=scroll.set)
        for rep in self.engine.ctx.params.get("_", []) or []:
            pass
        from ..core.repairer import all_repairs
        self._repairs = list(all_repairs())
        for rep in self._repairs:
            self.listbox.insert(tk.END, f"{rep.title}   [{rep.risk.value}]")

        foot = ttk.Frame(self, padding=12)
        foot.pack(fill=tk.X)
        ttk.Button(foot, text="Close", command=self.destroy).pack(side=tk.RIGHT)
        ttk.Button(foot, text="Roll back selected", command=self._rollback).pack(
            side=tk.RIGHT, padx=6)

    def _rollback(self) -> None:
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Nothing selected", "Select a repair first.")
            return
        rep = self._repairs[sel[0]]
        if not messagebox.askyesno("Confirm rollback",
                                   f"Undo '{rep.title}'?\n\n"
                                   f"This reverses the change made by the repair."):
            return
        result = self.engine.rollback(rep.id)
        messagebox.showinfo(
            "Rollback " + ("succeeded" if result.state == "verified" else "incomplete"),
            f"{result.message}\n\n"
            + ("Backups of any modified files are in the backup directory shown "
               "in the repair log." if result.applied else ""))
        self.master_app.status_var.set(f"Rollback: {result.state}")
        self.destroy()


# --------------------------------------------------------------------------
# Safety dialog
# --------------------------------------------------------------------------

_SAFETY_TEXT = """\
How Nexus System Doctor keeps repairs safe
==========================================

1. Diagnostics are read-only.
   A scan reads /proc, /sys and log files, and runs standard diagnostic tools
   (smartctl, sensors, journalctl, lspci, xinput). It cannot modify your
   system, and the test-suite proves this by running a full scan with write
   protection enabled.

2. Every repair is measured before and after.
   The application checks the state before applying a repair and again
   afterwards. A repair is only reported as successful if the second
   measurement shows the intended change. If it does not, the repair is
   reported as failed rather than assumed to have worked.

3. Nothing is applied without your consent.
   Repairs are listed with their risk, the exact steps they will take, whether
   they need your administrator password, and whether they can be undone.

4. Configuration files are backed up first.
   Any file a repair writes is copied to a timestamped backup directory, and
   the path is shown in the results. You can restore by hand even if this
   application is uninstalled.

5. Least privilege.
   The graphical interface never obtains a root shell. Administrator actions go
   through a small helper that accepts only a fixed list of diagnostic and
   tuning commands, and may only write inside system configuration
   directories - never to your home directory, and never to security files
   such as /etc/passwd or /etc/sudoers.

6. Reversible by design.
   Services are disabled rather than removed, startup entries are overridden
   rather than deleted, and every reversible repair offers a one-click undo.

7. Honest about uncertainty.
   When a check cannot get complete data (for example SMART without
   administrator rights) it says so and tells you what to run, instead of
   reporting the disk as healthy.
"""


class SafetyDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("How repairs are kept safe")
        self.geometry("700x520")
        self.transient(master)
        theme.setup(self)
        text = tk.Text(self, wrap=tk.WORD, padx=14, pady=12,
                       font=("DejaVu Sans Mono", 9))
        text.pack(fill=tk.BOTH, expand=True)
        text.insert("1.0", _SAFETY_TEXT)
        text.configure(state=tk.DISABLED)
        ttk.Button(self, text="Close", command=self.destroy).pack(pady=8)


def run(deep: bool = False, autoscan: bool = True) -> int:
    """Launch the graphical application."""
    app = NexusDoctorApp(deep=deep, autoscan=autoscan)
    app.mainloop()
    return 0
