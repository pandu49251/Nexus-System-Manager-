# How Nexus System Doctor keeps your system safe

This document describes exactly what the application is allowed to do, what it
is forbidden from doing, and how each guarantee is enforced and tested.

## 1. Diagnostics are read-only

A scan reads `/proc`, `/sys` and log files, and runs standard diagnostic tools
(`smartctl`, `sensors`, `lspci`, `journalctl`, `xinput`, `xfconf-query`). It
starts no services, installs nothing, and writes no files.

**How it is enforced.** Every single read and write in the diagnostic code goes
through one module, `core/executil.py`. When that module is put in sandbox mode
(`NEXUS_SANDBOX`), any write outside the sandbox raises `SandboxViolation`.

**How it is proven.**

- `test_readonly.py::test_full_scan_against_this_machine_writes_nothing` runs
  every check on the real machine with writes blocked and asserts that no
  violation occurred.
- `test_readonly.py::test_scan_does_not_modify_the_filesystem_tree` runs a
  scan against a copy of a machine and compares the size and modification time
  of every single file before and after — the diff must be empty.
- `test_purity.py` parses the source of every check and repair and fails the
  build if any of them calls `open()`, `os.remove`, `subprocess` or anything
  else that would bypass the controlled layer.

## 2. Verify, apply, verify

Each repair implements three methods:

- `available()` — is this repair meaningful on this machine right now?
- `apply()` — perform the change.
- `verify()` — measure the current state and report whether it is the desired
  one. This is run **before** and **after** `apply()`.

A repair is reported as **verified** only if the post-measurement passes. If
the command returns success but the system is unchanged, the repair is reported
as **failed** — never as successful.

**How it is proven.**

- `test_repairs.py::test_a_repair_that_did_not_work_is_reported_failed` applies
  every repair while leaving the machine deliberately unchanged, and asserts
  that **not one** of them comes back verified. This is the single most
  important test in the suite.
- `test_repairs.py::test_every_repair_verifies_when_the_change_really_happens`
  applies them against a machine that does change, and asserts that all
  seventeen verify, with a before-measurement that differs from the
  after-measurement.

## 3. Nothing happens without your consent

Repairs are never applied by a scan. The repair dialog shows, for each one:

- what it does, in plain language;
- every command it will run;
- its risk (low / medium / high);
- whether it needs your administrator password;
- whether it needs a reboot;
- whether it can be undone.

You tick the ones you want and confirm. `services.trim_autostart` is not even
offered until you have chosen which startup applications to disable — the
application does not guess.

A `--dry-run` mode (and the "review" step) walks the whole repair with every
mutation suppressed, so you can see the complete plan without a single byte
being written. `test_readonly.py::test_repairs_in_dry_run_change_nothing`
verifies that this is true by diffing the filesystem afterwards.

## 4. Any file that is modified is backed up first

Before writing, the file is copied to
`/var/lib/nexus-system-doctor/backups/<session>/` (or
`~/.local/share/nexus-system-doctor/backups/<session>/` when running as an
ordinary user), and the path is shown in the results pane. Restoring by hand is
a matter of copying the file back — you do not need this application to do it.

**How it is proven.** `test_repairs.py::test_modifying_a_config_file_makes_a_backup_first`
applies the `/etc/fstab` repair and then opens the backup to confirm it
contains the original contents.

## 5. Least privilege

The graphical interface never obtains a root shell. When an administrative
action is needed it calls a small helper through `pkexec`. That helper:

- accepts only a fixed list of binaries (`smartctl`, `systemctl`, `sysctl`,
  `mount`, `dpkg`, `apt-get`, `swapon`, `zramctl`, …);
- **refuses** interpreters and escalation tools (`sh`, `bash`, `python3`,
  `perl`, `sudo`, `su`, `pkexec`, `curl`, `wget`, `dd`, `mkfs`, `fdisk`);
- rejects any argument containing `;`, backticks, `$`, `&`, `|`, `<`, `>`,
  parentheses, quotes, newlines or glob characters, so a device name can never
  become a command;
- may only write inside a few system configuration directories (`/etc/`,
  `/usr/lib/nexus-system-doctor/`, `/var/lib/nexus-system-doctor/`);
- **never** writes to `/etc/passwd`, `/etc/shadow`, `/etc/group`,
  `/etc/sudoers`, `/etc/pam.d`, `/etc/security`, `/etc/ssh`, `/etc/polkit-1`,
  `/etc/hosts`, `/etc/crypttab`, `/etc/ld.so.preload` or anything under
  `/home` — mangling those could lock you out of the machine;
- restricts even *reads* performed as root, so `/etc/shadow` and SSH host keys
  are out of reach;
- backs up before every write, writes atomically (temp file + rename) and
  `fsync`s;
- logs every action to `/var/log/nexus-system-doctor-helper.log`.

**How it is proven.** `test_purity.py` exercises the allow-lists, the
metacharacter filter, the write deny-list and the read restrictions directly.

## 6. Reversible by design

- Services are **disabled**, never removed. Boot entries are **overridden**
  with `Hidden=true` in a per-user `.desktop` copy — exactly what Xfce's own
  "Application Autostart" dialog does — and never deleted. Deleting our copy
  restores the original vendor file.
- `/etc/fstab` is only rewritten after a successful test remount, and the
  original is backed up.
- Every reversible repair offers a one-click undo (Repair → Roll back a
  repair). The three that delete regenerable data (package archives,
  thumbnails) or configure packages say so up front and refuse to pretend
  otherwise.

## 7. Honest about uncertainty

When a check cannot obtain complete data — SMART without administrator rights,
no thermal sensors, an unreadable journal — it produces an informational
finding that says what is missing and the command to run, instead of reporting
a pass. A missing tool is normal on a minimal install and is reported as such,
never as "no problems found".

Findings carry a **confidence** value (`measured`, `direct`, `inferred`) that
is shown in the interface and in every report, so you can see how firm each
conclusion is.

## 8. Lightweight and offline

- The interface is Tkinter, which is part of every Linux Mint install; no GTK
  or Qt bindings are needed, and no web engine is involved.
- Scans run on a worker thread and the interface polls a queue 20 times a
  second, stopping when idle, so an idle window costs essentially nothing.
- No network access is required for any check or any repair, and no diagnostic
  data ever leaves the machine.

## 9. What it will not do

- It will not install packages. Where a package would help (for example
  `earlyoom`) it tells you the command; you decide.
- It will not delete your data. The three cleanup repairs remove caches that
  are regenerated automatically, and they say so.
- It will not change your `/home`. The helper's write allow-list excludes it
  entirely.
- It will not disable something because it merely looks unusual. Every repair
  is tied to a specific finding with evidence.
- It will not claim success. If verification does not pass, the repair is
  reported as failed.
