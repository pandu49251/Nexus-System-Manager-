"""
nexus_doctor.ui.theme
=====================

Colours, fonts and ttk style setup for the graphical interface.

The palette follows the Xfce/Adwaita conventions so the application looks
native on Linux Mint, works acceptably on dark themes (colours are chosen to
read against both), and never depends on an external asset that might be
missing on a minimal install.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

from ..core.models import Severity

# Severity palette: distinguishable without colour vision, and legible on both
# light and dark window backgrounds.
COLOURS = {
    "critical": "#c62828",
    "high": "#e0642a",
    "medium": "#b58900",
    "low": "#2a6fb5",
    "info": "#6b6b6b",
    "ok": "#2e7d32",
}

BG = "#f4f5f7"
FG = "#1d1d1d"
PANEL = "#ffffff"
HEADER_BG = "#123a5e"
HEADER_FG = "#ffffff"
ACCENT = "#1d6fa5"
BORDER = "#d4d8dd"
MUTED = "#6a7076"

SYMBOLS = {
    "critical": "!!",
    "high": "!",
    "medium": "-",
    "low": ".",
    "info": "i",
    "ok": "OK",
}


def severity_colour(severity: Severity) -> str:
    return COLOURS.get(severity.value if hasattr(severity, "value") else str(severity),
                       MUTED)


def setup(root: tk.Misc) -> None:
    """Apply the application style to a Tk root window."""
    style = ttk.Style(root)
    for name in ("clam", "alt", "default"):
        if name in style.theme_names():
            try:
                style.theme_use(name)
                break
            except tk.TclError:
                continue

    default = tkfont.nametofont("TkDefaultFont")
    family = default.cget("family")
    size = max(9, default.cget("size"))

    style.configure(".", background=BG, foreground=FG, font=(family, size))
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL, relief="flat")
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Header.TFrame", background=HEADER_BG)
    style.configure("Header.TLabel", background=HEADER_BG, foreground=HEADER_FG,
                    font=(family, size + 6, "bold"))
    style.configure("HeaderSub.TLabel", background=HEADER_BG, foreground="#cfe3f2",
                    font=(family, max(8, size - 1)))
    style.configure("Muted.TLabel", background=BG, foreground=MUTED,
                    font=(family, max(8, size - 1)))
    style.configure("Card.TFrame", background=PANEL, relief="ridge", borderwidth=1)
    style.configure("TButton", padding=(10, 5))
    style.configure("Accent.TButton", padding=(10, 5), background=ACCENT)
    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    borderwidth=0, rowheight=max(20, size * 2))
    style.configure("Treeview.Heading", font=(family, size, "bold"))
    style.configure("TProgressbar", background=ACCENT, troughcolor="#e2e6ea")
    style.configure("TNotebook", background=BG)
    style.configure("TNotebook.Tab", padding=(10, 4))
    style.configure("TCheckbutton", background=PANEL)
    style.configure("Severe.Horizontal.TProgressbar", background=COLOURS["critical"])

    root.option_add("*Text.background", PANEL)
    root.option_add("*Text.foreground", FG)
    root.option_add("*Text.borderWidth", 0)
    root.option_add("*Text.highlightThickness", 0)
