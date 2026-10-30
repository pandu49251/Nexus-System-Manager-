#!/usr/bin/env python3
"""
Run the whole Nexus System Doctor test suite.

    python3 tests/run_tests.py              # everything
    python3 tests/run_tests.py -v           # verbose
    python3 tests/run_tests.py test_repairs # one module

An X server is started automatically (Xvfb) when the machine has none, so the
graphical interface is exercised even on a headless build machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

X_DISPLAY = ":99"


def _display_is_usable() -> bool:
    if not os.environ.get("DISPLAY"):
        return False
    try:
        import tkinter
        probe = tkinter.Tk()
        probe.withdraw()
        probe.destroy()
        return True
    except Exception:
        return False


def start_virtual_display():
    """Start Xvfb so the GUI tests can run headless. Returns the process."""
    if _display_is_usable():
        return None
    xvfb = shutil.which("Xvfb")
    if not xvfb:
        print("note: no X display and no Xvfb - GUI tests will be skipped")
        return None
    proc = subprocess.Popen([xvfb, X_DISPLAY, "-screen", "0", "1280x900x24"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.environ["DISPLAY"] = X_DISPLAY
    for _ in range(50):
        time.sleep(0.1)
        if _display_is_usable():
            print(f"note: started Xvfb on {X_DISPLAY} for the GUI tests")
            return proc
    proc.terminate()
    print("note: Xvfb did not come up - GUI tests will be skipped")
    os.environ.pop("DISPLAY", None)
    return None


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    verbosity = 2 if "-v" in argv or "--verbose" in argv else 1
    names = [a for a in argv if not a.startswith("-")]

    xvfb = start_virtual_display()
    # A display is needed before harness/app import their Tk bits.
    try:
        loader = unittest.TestLoader()
        if names:
            suite = unittest.TestSuite(
                [loader.loadTestsFromName(n if n.startswith("test_") else "test_" + n)
                 for n in names])
        else:
            suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)

        print("=" * 72)
        print("Nexus System Doctor - test suite")
        print("=" * 72)
        runner = unittest.TextTestRunner(verbosity=verbosity)
        result = runner.run(suite)
    finally:
        if xvfb:
            xvfb.terminate()
            try:
                xvfb.wait(timeout=10)
            except subprocess.TimeoutExpired:
                xvfb.kill()
        import harness
        harness.cleanup()

    print()
    print("=" * 72)
    print(f"tests run: {result.testsRun}   "
          f"failures: {len(result.failures)}   "
          f"errors: {len(result.errors)}   "
          f"skipped: {len(result.skipped)}")
    print("=" * 72)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
