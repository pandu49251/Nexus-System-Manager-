#!/usr/bin/env python3
"""
Build a browsable documentation site from the project's Markdown files.

    python3 tools/build_docs_site.py          # writes docs/site/
    python3 tools/build_docs_site.py --serve  # ... and serve it on :8000

The output is a static site with no external stylesheets, fonts, scripts or
images: it opens correctly offline, from a file:// path, or years from now.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "site")
REPO = "https://github.com/Pandu49251/nexus-system-doctor"

try:
    import markdown
    HAVE_MARKDOWN = True
except ImportError:                                   # pragma: no cover
    HAVE_MARKDOWN = False


PAGES = [
    ("index.html", "README.md", "Overview", "What it is, what it checks, what it repairs"),
    ("install.html", "INSTALL.md", "Install", "Packages, dependencies, troubleshooting"),
    ("safety.html", "SAFETY.md", "Safety", "How your system is protected, and how it is proven"),
    ("changelog.html", "CHANGELOG.md", "Changelog", "What is in 1.0.0"),
]

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, "DejaVu Sans", sans-serif;
       background: #f4f5f7; color: #1b1b1b; line-height: 1.6; }
a { color: #1d6fa5; }
.layout { display: flex; align-items: flex-start; }
nav { position: sticky; top: 0; height: 100vh; overflow-y: auto;
      width: 260px; flex: 0 0 260px; background: #123a5e; color: #dbe8f2;
      padding: 22px 0; }
nav h1 { font-size: 15px; margin: 0 20px 2px; color: #fff; letter-spacing: .3px; }
nav .ver { font-size: 11.5px; margin: 0 20px 18px; color: #8fb6d4; }
nav a { display: block; padding: 8px 20px; color: #cfe3f2; text-decoration: none;
        font-size: 13.5px; border-left: 3px solid transparent; }
nav a:hover { background: #194b78; color: #fff; }
nav a.active { background: #1d6fa5; color: #fff; border-left-color: #7fd1ff; }
nav a .sub { display: block; font-size: 11px; color: #8fb6d4; }
nav a.active .sub { color: #cfe8fa; }
nav .repo { margin: 22px 20px 0; padding-top: 14px; border-top: 1px solid #2b5b83;
            font-size: 12px; }
nav .repo a { padding: 2px 0; color: #7fd1ff; }
main { flex: 1 1 auto; min-width: 0; padding: 28px 40px 80px; }
.wrap { max-width: 940px; }
main h1 { font-size: 25px; margin: 0 0 4px; color: #123a5e; }
main h2 { font-size: 19px; margin: 30px 0 8px; padding-bottom: 5px;
          border-bottom: 2px solid #dde2e7; }
main h3 { font-size: 15px; margin: 22px 0 6px; }
code { background: #eceff2; padding: 1px 5px; border-radius: 3px;
       font-family: "DejaVu Sans Mono", monospace; font-size: 12.5px; }
pre { background: #f6f8fa; border: 1px solid #e2e7ea; border-radius: 6px;
      padding: 12px 14px; overflow-x: auto; }
pre code { background: none; padding: 0; font-size: 12.5px; }
table { border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 13.5px;
        background: #fff; }
th, td { border: 1px solid #e2e7ea; padding: 7px 10px; text-align: left; }
th { background: #eef3f7; }
blockquote { margin: 12px 0; padding: 2px 14px; border-left: 4px solid #1d6fa5;
             color: #444; background: #fff; }
img { max-width: 100%; border: 1px solid #dde2e7; border-radius: 6px; margin: 10px 0; }
hr { border: 0; border-top: 1px solid #dde2e7; margin: 26px 0; }
.card { background: #fff; border: 1px solid #e2e7ea; border-radius: 8px;
        padding: 16px 18px; margin: 14px 0; }
.badge { display: inline-block; background: #1d6fa5; color: #fff; font-size: 11px;
         font-weight: 700; padding: 3px 9px; border-radius: 10px; margin-right: 6px; }
@media (max-width: 820px) {
  .layout { display: block; }
  nav { position: static; width: auto; height: auto; }
  main { padding: 20px; }
}
"""


def md_to_html(text: str) -> str:
    if HAVE_MARKDOWN:
        return markdown.markdown(
            text, extensions=["tables", "fenced_code", "toc", "sane_lists"])
    return _fallback(text)


def _fallback(text: str) -> str:
    """Deliberately small Markdown subset renderer (no dependencies)."""
    out, in_code, buf = [], False, []

    def flush():
        if buf:
            out.append("<p>" + _inline("\n".join(buf)) + "</p>")
            buf.clear()

    for line in text.splitlines():
        if line.startswith("```"):
            if in_code:
                out.append("<pre><code>" + html.escape("\n".join(buf)) + "</code></pre>")
                buf.clear()
            flush()
            in_code = not in_code
            continue
        if in_code:
            buf.append(line)
            continue
        if not line.strip():
            flush()
        elif line.startswith("#"):
            flush()
            level = min(6, len(line) - len(line.lstrip("#")))
            out.append(f"<h{level}>{_inline(line.lstrip('# '))}</h{level}>")
        elif line.startswith(("|", "|-")):
            buf.append(line)
        elif re.match(r"^\s*([-*+]|\d+\.)\s", line):
            flush()
            out.append("<li>" + _inline(re.sub(r"^\s*([-*+]|\d+\.)\s", "", line)) + "</li>")
        else:
            buf.append(line)
    flush()
    return "\n".join(out)


def _inline(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def _nav(current: str) -> str:
    items = []
    for page, _src, label, sub in PAGES + [("report.html", None, "Sample report",
                                            "A real scan of the IdeaPad, after repairs"),
                                           ("screenshots.html", None, "Screenshots",
                                            "The main window and repair dialog")]:
        active = " class='active'" if page == current else ""
        items.append(f"<a href='{page}'{active}>{label}<span class='sub'>{sub}</span></a>")
    return f"""<nav>
<h1>Nexus System Doctor</h1>
<p class="ver">v1.0.0 &middot; Linux Mint Xfce</p>
{''.join(items)}
<div class="repo">
  Source<br><a href="{REPO}">github.com/Pandu49251/<br>nexus-system-doctor</a>
</div>
</nav>"""


def _page(title: str, body: str, current: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} - Nexus System Doctor</title>
<style>{CSS}</style></head>
<body><div class="layout">
{_nav(current)}
<main><div class="wrap">
{body}
</div></main>
</div></body></html>
"""


def build() -> str:
    os.makedirs(OUT, exist_ok=True)
    assets = os.path.join(OUT, "assets")
    os.makedirs(assets, exist_ok=True)

    for page, source, title, _sub in PAGES:
        path = os.path.join(ROOT, source)
        with open(path, encoding="utf-8") as fh:
            body = md_to_html(fh.read())
        body = body.replace('src="docs/screenshots/', 'src="assets/')
        with open(os.path.join(OUT, page), "w", encoding="utf-8") as fh:
            fh.write(_page(title, body, page))

    # sample report: already self-contained HTML, served as its own page
    report = os.path.join(ROOT, "docs", "sample-report.html")
    if os.path.isfile(report):
        shutil.copyfile(report, os.path.join(OUT, "report.html"))

    for name in ("main-window.png", "repair-dialog.png"):
        src = os.path.join(ROOT, "docs", "screenshots", name)
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(assets, name))

    shots = ["<h1>Screenshots</h1>",
             "<p>Captured from the real Tkinter interface, running against the "
             "synthetic IdeaPad S145-14AST used by the test suite.</p>"]
    for name, caption in (("main-window.png", "The main window after a scan: findings "
                                              "grouped by area and ordered by severity, "
                                              "with root cause, recommended actions and "
                                              "evidence on the right."),
                          ("repair-dialog.png", "The repair dialog: every repair with its "
                                                "risk, the exact steps it will take, and "
                                                "whether it needs your password.")):
        if os.path.isfile(os.path.join(assets, name)):
            shots.append(f"<h2>{caption.split(':')[0]}</h2>"
                         f"<img src='assets/{name}' alt='{html.escape(caption)}'>"
                         f"<p>{html.escape(caption)}</p>")
    with open(os.path.join(OUT, "screenshots.html"), "w", encoding="utf-8") as fh:
        fh.write(_page("Screenshots", "\n".join(shots), "screenshots.html"))

    files = sorted(os.listdir(OUT))
    print(f"documentation site written to {OUT}")
    print("  " + ", ".join(files))
    return OUT


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true",
                        help="serve the site on 0.0.0.0:8000 after building")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    out = build()
    if args.serve:
        os.chdir(out)
        sys.exit(os.execvp("python3", ["python3", "-m", "http.server",
                                       str(args.port), "--bind", "0.0.0.0"]))
