# Nexus System Doctor v1.0

![Tests](https://github.com/Pandu49251/nexus-system-doctor/actions/workflows/tests.yml/badge.svg)

Repository: <https://github.com/Pandu49251/nexus-system-doctor>

```bash
git clone https://github.com/Pandu49251/nexus-system-doctor.git
cd nexus-system-doctor
sudo apt install ./dist/nexus-system-doctor_1.0.0_all.deb   # or ./packaging/build-deb.sh
```

A desktop application for Linux that finds out what is actually wrong with a
machine, explains it in plain language, and repairs what can be repaired
safely — always proving the repair worked before saying so.

It was built for one specific, very common machine: a **Lenovo IdeaPad
S145-14AST (machine type 81ST)** with an **AMD dual-core A6-9225**, **4 GB of
RAM**, a **1 TB mechanical hard disk**, **AMD Radeon integrated graphics**,
running **Linux Mint 21.3 Xfce**. Everything it checks and repairs is
appropriate for an older, resource-constrained laptop, and it never assumes
hardware that is not there.

The application itself is deliberately small: pure Python with the standard
Tkinter interface, no background daemon, no network access, and no Python GUI
toolkit beyond what Mint already ships.

---

## What it checks

| Area | Examples of what it finds |
|---|---|
| **Keyboard and input** | Keys that repeat too slowly or too fast, a keyboard layout that does not match the locale, a modifier key that is stuck down, PS/2 controller errors, a device disabled in X11 |
| **System lag** | High iowait (CPU idle but waiting for the disk), load above the core count, a CPU stuck at its minimum frequency, slow boot, background services saturating the disk |
| **Slow applications** | Memory pressure forcing paging to a slow disk, a mechanical disk with a scheduler tuned for SSDs, filesystem metadata errors, an oversized dirty-write buffer |
| **Memory pressure** | No swap space at all, OOM-killer events, low available memory, overcommit, no userspace OOM guard, zswap/zram disabled |
| **HDD health** | Reallocated, pending and uncorrectable sectors, command time-outs, interface CRC errors, SATA link problems, head parking, power-on hours, whether smartd is monitoring the drive |
| **Thermal** | Hot CPU packages, throttling (a CPU that will not reach its rated speed), missing or failed fan control |
| **Battery** | Wear relative to design capacity, charge-cycle count, whether a charge threshold is set, missing laptop power management |
| **Drivers** | Whether the GPU uses the modern `amdgpu` driver, missing firmware, a missing Lenovo platform driver, failed modules, tainted kernel |
| **Software errors** | Half-configured packages, broken dependencies, service crash loops, repeated journal errors, filesystem errors awaiting a check |
| **Services and startup** | Failed systemd units, services for hardware that does not exist, desktop search indexing a mechanical disk, ten applications starting at login, apt timers seizing the disk |
| **Filesystem and space** | Nearly full partitions, inode exhaustion, an oversized journal, package and thumbnail caches, access-time writes on every read |

Every finding carries the command or sysfs file that produced it, so any claim
can be checked by hand.

---

## What it repairs

Seventeen repairs are implemented. All of them are opt-in, all are measured
before and after, and all reversible ones can be undone from the Repair menu.

| Repair | What it does | Risk | Undo |
|---|---|---|---|
| `cleanup.apt_cache` | Clears downloaded `.deb` archives | low | no (re-downloaded if ever needed) |
| `cleanup.journal` | Vacuums the system log and caps it at 200 MB / 14 days | low | yes |
| `cleanup.thumbnails` | Clears the image thumbnail cache | low | no (regenerated automatically) |
| `cpu.governor` | Switches the CPU governor from `powersave` to `schedutil` | low | yes |
| `memory.swappiness` | Reduces swap eagerness from 60 to 10 | low | yes |
| `memory.zram_swap` | Creates a compressed 50%-of-RAM zram swap device | medium | yes |
| `storage.dirty_ratio` | Caps the dirty-write buffer at 128 MB / 32 MB | low | yes |
| `storage.io_scheduler` | Sets `bfq` on the mechanical disk via a udev rule | low | yes |
| `storage.noatime` | Adds `noatime` to `/` and `/home` in `/etc/fstab` | medium | yes |
| `storage.enable_smartd` | Enables smartd so disk failures are reported early | low | yes |
| `services.disable_indexers` | Masks the desktop search indexer | low | yes |
| `services.disable_unused` | Disables ModemManager/Bluetooth when no such hardware exists | low | yes |
| `services.disable_apt_timers` | Stops apt's daily timers from stalling the disk | low | yes |
| `services.trim_autostart` | Disables *user-selected* startup applications | low | yes |
| `xfce.compositing_off` | Turns off Xfce window compositing | low | yes |
| `input.keyrepeat` | Sets a responsive key repeat (250 ms / 35 per second) and persists it | low | yes |
| `input.layout` | Applies the correct keyboard layout and persists it | low | yes |
| `software.fix_dpkg` | Runs `dpkg --configure -a` to finish an interrupted install | medium | no |

`services.trim_autostart` is deliberately never offered on its own: the
application will not guess which of your startup programs you wanted. It
appears only after you choose entries.

---

## Running it

```bash
sudo apt install ./nexus-system-doctor_1.0.0_all.deb
nexus-doctor                  # graphical interface
nexus-doctor --cli --scan     # text report in a terminal
```

For the most complete diagnostics, run it as root so SMART data, `dmidecode`
and the journal are readable:

```bash
sudo nexus-doctor --cli --scan --deep
nexus-doctor --gui            # from a root shell, if you prefer the window
```

When it runs without administrator rights it still works, and it says plainly
which evidence it could not collect instead of claiming the disk is healthy.

### Command line

```
nexus-doctor --scan [--deep] [--json FILE] [--report FILE] [--text]
nexus-doctor --list-checks
nexus-doctor --list-repairs
nexus-doctor --scan --repair [--safe] [--dry-run] [--yes]
nexus-doctor --rollback <id>
```

The exit status encodes the worst finding (2 critical, 1 high, 0 otherwise),
so the tool can be used from scripts.

---

## How safety works

1. **Diagnostics are read-only** — proven by a test that runs a full scan with
   write protection enabled and a second that diffs the whole filesystem tree.
2. **Verify, apply, verify** — a repair is reported as successful only if the
   second measurement shows the intended state. A repair whose command
   "succeeded" but changed nothing is reported as **failed**.
3. **Backups** — every file a repair modifies is copied to a timestamped
   directory first, and the path is shown in the results.
4. **Least privilege** — the graphical interface never holds a root shell.
   Administrative actions go through a small helper that accepts only a fixed
   list of commands and may only write inside system configuration
   directories, never to `/etc/passwd`, `/etc/sudoers` or your home directory.
5. **Honest degradation** — a check that cannot get data says so rather than
   reporting a pass.

See [SAFETY.md](SAFETY.md) for the full model, and
[INSTALL.md](INSTALL.md) for installation, dependencies and troubleshooting.

---

## Screenshots and reports

![The main window](docs/screenshots/main-window.png)

![The repair dialog](docs/screenshots/repair-dialog.png)

A sample report generated against the reference machine, including a full
repair run, is in [docs/sample-report.html](docs/sample-report.html).

The report (HTML, Markdown, plain text or JSON) contains the machine identity,
every finding ordered by severity, the root cause, the recommended action and
the evidence with the command that produced it. The HTML report is a single
self-contained file: no stylesheets, fonts, scripts or images are fetched from
anywhere, so it opens correctly offline and years later.

---

## Development

```bash
python3 tools/make_fixture.py      # rebuild the synthetic IdeaPad
python3 tests/run_tests.py         # 67 tests, including the GUI
packaging/build-deb.sh             # build the .deb
```

The test suite runs the entire engine against a synthetic copy of the target
laptop — a worn disk with real SMART failures, 4 GB RAM with no swap, a stuck
modifier key, the wrong layout, a hot CPU, broken packages, failed units, a
1.4 GB journal — and asserts that every fault is found, every repair verifies,
and a repair that changes nothing is reported as failed.

## Licence

MIT. See [LICENSE](LICENSE).
