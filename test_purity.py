"""
Safety test: the diagnostic code cannot touch the operating system directly.

Every read, write and subprocess call is funnelled through ``core.executil``
so that it can be sandboxed, time-limited, logged and redirected at a fake
machine.  If a check or repair sidestepped that layer by calling ``open()``,
``subprocess`` or ``os.system`` itself, the sandbox used by
``test_readonly.py`` could not protect the machine - so this is asserted
structurally, in addition to being tested behaviourally.
"""

from __future__ import annotations

import ast
import json
import os
import unittest
from pathlib import Path

import harness

ROOT = Path(harness.ROOT)

# Modules that are allowed to touch the OS directly because they *are* the
# controlled boundary, or because they only ever open the file the user asked
# them to write.
EXEMPT = {
    ROOT / "nexus_doctor" / "core" / "executil.py",
    ROOT / "nexus_doctor" / "core" / "privileges.py",
    ROOT / "nexus_doctor" / "privileged_helper.py",
}

#: os.<name> calls that would bypass the controlled layer.
OS_FORBIDDEN = {
    "system", "popen", "execv", "execve", "execvp", "execl", "execle", "execlp",
    "spawnl", "spawnv", "spawnve", "fork", "forkpty",
    "remove", "unlink", "rmdir", "rename", "renames", "replace", "truncate",
    "chmod", "chown", "lchown", "mkdir", "makedirs", "symlink", "link",
}
#: Bare builtins that must not be used for I/O or code execution.
BUILTIN_FORBIDDEN = {"open", "exec", "eval", "compile", "__import__"}
#: Modules that provide unmediated OS access.
MODULE_FORBIDDEN = {"subprocess", "shutil", "pty", "commands", "tempfile"}


def _walk_py(base: Path):
    for path in sorted(base.rglob("*.py")):
        if path.name == "harness.py":
            continue
        if "__pycache__" in path.parts:
            continue
        yield path


def _module_of(node: ast.AST) -> str:
    """Return 'module.attr' for an attribute chain, or the bare name."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class PurityTests(unittest.TestCase):
    def test_no_direct_os_access_in_checks_and_repairs(self):
        offenders = []
        for base in (ROOT / "nexus_doctor" / "checks",
                     ROOT / "nexus_doctor" / "repairs"):
            for path in _walk_py(base):
                if path in EXEMPT:
                    continue
                tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        names = ([a.name for a in node.names]
                                 if isinstance(node, ast.Import)
                                 else [node.module or ""])
                        for name in names:
                            if name.split(".")[0] in MODULE_FORBIDDEN:
                                offenders.append(f"{path.name}: imports {name}")
                    if isinstance(node, ast.Call):
                        target = _module_of(node.func)
                        head = target.split(".")[0]
                        if head in MODULE_FORBIDDEN:
                            offenders.append(f"{path.name}: calls {target}()")
                        elif head == "os" and len(target.split(".")) == 2 \
                                and target.split(".")[1] in OS_FORBIDDEN:
                            offenders.append(f"{path.name}: calls {target}()")
                        elif target in BUILTIN_FORBIDDEN:
                            offenders.append(f"{path.name}: calls {target}()")
        self.assertEqual([], offenders,
                         "checks/repairs must go through core.executil:\n  "
                         + "\n  ".join(offenders))

    def test_no_shell_anywhere(self):
        """No command is ever handed to a shell, so a filename is never code."""
        offenders = []
        for path in _walk_py(ROOT / "nexus_doctor"):
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and \
                        any(kw.arg == "shell" for kw in node.keywords):
                    offenders.append(f"{path.name}: passes shell= to a call")
                if isinstance(node, ast.Call) and \
                        _module_of(node.func).startswith("os.popen"):
                    offenders.append(f"{path.name}: uses os.popen")
        self.assertEqual([], offenders, "shell=True is never permitted")

    def test_every_subprocess_call_has_a_timeout(self):
        """A wedged disk must never be able to hang the application."""
        target = (ROOT / "nexus_doctor" / "core" / "executil.py",
                  ROOT / "nexus_doctor" / "privileged_helper.py")
        offenders = []
        for path in target:
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and \
                        _module_of(node.func).endswith(("subprocess.run",
                                                        "subprocess.Popen",
                                                        "subprocess.check_output")):
                    if not any(kw.arg == "timeout" for kw in node.keywords):
                        offenders.append(f"{path.name}: subprocess without timeout")
        self.assertEqual([], offenders)

    def test_every_executil_command_has_a_default_timeout(self):
        src = (ROOT / "nexus_doctor" / "core" / "executil.py").read_text(encoding="utf-8")
        self.assertIn("def run(\n    argv: Sequence[str],\n    timeout: float = 15.0",
                      src)

    def test_helper_denies_unlisted_binaries(self):
        """The helper must refuse to execute anything off its allow-list."""
        harness.use_fixture(root=True)
        from nexus_doctor import privileged_helper as helper
        for bad in (["bash", "-c", "id"], ["shutdown", "now"],
                    ["passwd"], ["visudo"], ["dd", "if=/dev/zero", "of=/dev/sda"],
                    ["python3", "-c", "print(1)"], ["curl", "http://x"],
                    ["sudo", "id"], ["mkfs", "/dev/sda1"], ["sh", "-c", "id"],
                    ["xargs", "rm"], ["env", "id"]):
            response = json.loads(helper.handle(
                {"op": "run", "argv": bad, "timeout": 5}))
            self.assertFalse(response["ok"], f"{bad[0]} should have been refused")
            self.assertTrue("not permitted" in response.get("error", "")
                            or "allow-list" in response.get("error", ""),
                            f"{bad[0]}: {response.get('error')}")
        # rm is allow-listed (it masks units), but must still refuse /tmp
        response = json.loads(helper.handle({"op": "run", "argv": ["rm", "-rf", "/tmp"]}))
        self.assertFalse(response["ok"], "rm must not delete outside /etc")

        for good in ("smartctl", "systemctl", "apt-get", "dpkg", "sysctl",
                     "swapon", "swapoff", "modprobe", "mount", "journalctl",
                     "udevadm", "sensors", "iostat", "hdparm", "zramctl",
                     "mkswap", "rm", "chmod", "mkdir", "touch", "install",
                     "dmidecode", "blkid", "lsblk", "findmnt", "tune2fs"):
            self.assertIn(good, helper.ALLOWED_BINARIES,
                          f"{good} must be on the helper allow-list")
            response = json.loads(helper.handle(
                {"op": "run", "argv": [good, "--nexus-nonexistent-flag"], "timeout": 5}))
            self.assertNotIn("allow-list", response.get("error", ""),
                             f"{good} was refused by the allow-list: {response}")

    def test_helper_denies_unlisted_write_paths(self):
        harness.use_fixture(root=True)
        from nexus_doctor import privileged_helper as helper
        for bad in ("/root/.profile", "/home/user/.bashrc", "/etc/passwd",
                    "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/x",
                    "/etc/pam.d/login", "/etc/security/limits.conf",
                    "/etc/polkit-1/rules.d/x", "/etc/hosts",
                    "relative/path", "/tmp/escape",
                    "/etc/../home/user/.bashrc"):
            self.assertFalse(helper._path_allowed(bad), f"{bad} must be denied")
        for good in ("/etc/fstab", "/etc/sysctl.d/99-nexus-doctor-disk.conf",
                     "/etc/systemd/system/nexus-zram.service",
                     "/etc/modules-load.d/nexus-zram.conf",
                     "/etc/default/grub",
                     "/etc/systemd/journald.conf.d/nexus-doctor.conf",
                     "/usr/lib/nexus-system-doctor/zram-setup.sh"):
            self.assertTrue(helper._path_allowed(good), f"{good} must be allowed")

    def test_helper_rejects_metacharacters(self):
        harness.use_fixture(root=True)
        from nexus_doctor import privileged_helper as helper
        for bad in ("smartctl; rm -rf /", "/dev/sda && touch /x", "a`id`", "b|id",
                    "$(id)", "/dev/sda\nreboot", "*", "a$(whoami)", "x > /etc/passwd"):
            response = json.loads(helper.handle(
                {"op": "run", "argv": ["smartctl", bad], "timeout": 5}))
            self.assertFalse(response["ok"], f"{bad!r} must be rejected")
            self.assertIn("forbidden character", response.get("error", ""),
                          f"{bad!r}: {response}")
        for good in ("/dev/sda", "-a", "99-nexus-doctor.conf", "schedutil", "bfq"):
            response = json.loads(helper.handle(
                {"op": "run", "argv": ["smartctl", good], "timeout": 5}))
            self.assertNotIn("forbidden character", response.get("error", ""),
                             f"{good!r} must be accepted")

    def test_helper_restricts_privileged_reads(self):
        """Running as root must not mean 'read any file on the system'."""
        harness.use_fixture(root=True)
        from nexus_doctor import privileged_helper as helper
        for bad in ("/etc/shadow", "/etc/gshadow", "/etc/sudoers",
                    "/etc/ssh/ssh_host_rsa_key", "/etc/ssl/private/x.key",
                    "/etc/crypttab", "/etc/polkit-1/rules.d/x",
                    "/home/user/.ssh/id_rsa", "/home/user/.bashrc",
                    "/var/lib/nexus-system-doctor/../../etc/shadow"):
            self.assertFalse(helper._read_allowed(bad), f"{bad} must not be readable")
        for good in ("/etc/fstab", "/proc/meminfo", "/sys/block/sda/queue/scheduler",
                     "/var/log/syslog", "/run/udev/data/b8:0",
                     "/var/lib/nexus-system-doctor/state.json",
                     "/usr/lib/nexus-system-doctor/zram-setup.sh"):
            self.assertTrue(helper._read_allowed(good), f"{good} must be readable")

    def test_checks_do_not_depend_on_the_repair_layer(self):
        """A scan must be able to run without any repair code being imported."""
        offenders = []
        for path in _walk_py(ROOT / "nexus_doctor" / "checks"):
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("repairs"):
                    offenders.append(f"{path.name}: imports from repairs")
                if isinstance(node, ast.Import) and \
                        any(a.name.endswith("repairs") for a in node.names):
                    offenders.append(f"{path.name}: imports repairs")
        self.assertEqual([], offenders,
                         "checks must not depend on the repair layer")

    def test_fixture_files_exist(self):
        harness.ensure_fixture()
        self.assertTrue(os.path.isdir(harness.FIXTURE_DIR))
        cmds = os.path.join(harness.FIXTURE_DIR, "commands.json")
        self.assertTrue(os.path.isfile(cmds))
        import json
        with open(cmds, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("tools", data)
        self.assertIn("commands", data)
        self.assertTrue(os.path.isdir(harness.FIXTURE_ROOTFS))


if __name__ == "__main__":
    unittest.main()
