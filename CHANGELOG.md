# Changelog

## 1.0.0 - first release

### Diagnostics (15 checks, 55 findings on the reference machine)

- **Machine identity** from DMI: vendor, product, version, serial, BIOS, chassis.
- **Hard disk health**: full SMART attribute analysis - reallocated, pending and
  offline-uncorrectable sectors, command time-outs, interface CRC errors, head
  parking, power-on hours, rotation rate, self-test result, and whether `smartd`
  is monitoring the drive.
- **Filesystem and space**: usage and inode use per mount point, filesystem
  errors, pending fsck, oversized journal, package and thumbnail caches,
  largest directories.
- **Deep check**: a real disk benchmark (sustained write with `fsync`,
  sequential read, 256 random 4 KiB reads) that cleans up after itself.
- **CPU and thermal**: model, cores, frequency versus rated maximum, throttling,
  governor, load, iowait, per-zone temperatures.
- **Memory**: total, available, swap, commit versus limit, OOM-kill events,
  overcommit, zswap/zram state, presence of a userspace OOM guard.
- **Battery**: wear against design capacity, charge cycles, energy now/full,
  charge thresholds, power-management tooling.
- **Graphics**: GPU and driver identification from `lspci -k`, DRM device,
  renderer string, VRAM, Xfce compositing state.
- **Keyboard and input**: layout versus locale, key repeat rate, stuck modifier
  keys, PS/2 controller errors, disabled input devices, touchpad presence.
- **Services, startup and boot**: failed units, boot time and blame, autostart
  entries, indexers and other heavy background work, services for absent
  hardware, apt's automatic timers.
- **System configuration**: I/O scheduler versus disk type, access-time
  updating, dirty-write buffer sizing, swap eagerness.
- **Kernel, modules and drivers**: version, command line, taint, secure boot,
  failed modules, missing platform drivers.
- **Software errors**: half-configured and broken packages, service crash loops,
  journal error frequency with the sources identified.

### Repairs (17, all verified before and after)

Cleanup (3), CPU governor (1), memory (2), storage (5), services and startup
(4), desktop and input (3), package repair (1). All reversible except the three
that delete regenerable cache data or configure packages, which say so.

### Interface

- Tkinter/ttk window: findings grouped by area and ordered by severity, a detail
  pane with root cause, impact, recommended actions and the evidence with the
  command that produced it, a progress bar, and a status line.
- Repair dialog with risk, steps, privilege and reboot badges, and a
  "select all low-risk" shortcut.
- Rollback dialog.
- Reports in HTML (self-contained), Markdown, plain text and JSON.
- Command-line interface for headless use and scripting, with an exit status
  that encodes the worst finding.

### Safety

- Single point of OS contact (`core/executil.py`): no shell, mandatory timeout,
  audit logging, and sandboxable.
- Allow-listed privileged helper invoked through `pkexec`, with metacharacter
  rejection and write/read deny-lists.
- Backups before every configuration write.
- 67 tests, including a GUI test run headlessly against a virtual X server.
