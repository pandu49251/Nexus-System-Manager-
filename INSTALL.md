# Installing Nexus System Doctor

```bash
git clone https://github.com/Pandu49251/nexus-system-doctor.git
cd nexus-system-doctor
```

## Recommended: the .deb package

```bash
sudo apt install ./nexus-system-doctor_1.0.0_all.deb
```

This installs:

| Path | Contents |
|---|---|
| `/opt/nexus-system-doctor/` | the application (self-contained) |
| `/usr/bin/nexus-doctor` | launcher |
| `/usr/lib/nexus-system-doctor/privileged-helper` | the allow-listed helper used by pkexec |
| `/usr/share/applications/nexus-system-doctor.desktop` | menu entry (System) |
| `/usr/share/icons/hicolor/scalable/apps/nexus-system-doctor.svg` | icon |
| `/usr/share/polkit-1/actions/org.nexus.system-doctor.policy` | policy that lets the GUI ask for your password |

To remove it:

```bash
sudo apt remove nexus-system-doctor      # keeps /var/lib/nexus-system-doctor
sudo apt purge nexus-system-doctor       # also removes it
```

## Manual installation (no package)

```bash
sudo mkdir -p /opt/nexus-system-doctor
sudo cp -r nexus_doctor /opt/nexus-system-doctor/
sudo install -m 0755 nexus-doctor /opt/nexus-system-doctor/nexus-doctor
sudo ln -sf /opt/nexus-system-doctor/nexus-doctor /usr/bin/nexus-doctor
sudo mkdir -p /usr/lib/nexus-system-doctor
sudo install -m 0755 share/privileged-helper /usr/lib/nexus-system-doctor/
sudo install -m 0644 share/nexus-system-doctor.desktop /usr/share/applications/
sudo install -m 0644 share/nexus-system-doctor.svg \
     /usr/share/icons/hicolor/scalable/apps/
sudo install -m 0644 share/org.nexus.system-doctor.policy /usr/share/polkit-1/actions/
```

Or simply run it from the source tree:

```bash
./nexus-doctor
```

## Dependencies

**Required**

- `python3` (>= 3.8)
- `python3-tk` — the graphical interface (Tkinter)
- `procps` — `ps`, used to inspect running processes

**Recommended** (the application works without them, but reports fewer facts)

- `smartmontools` — disk health (SMART). Without it the disk cannot be assessed.
- `lm-sensors` — temperatures and fan speeds
- `pciutils` — `lspci`, for graphics and driver identification
- `mesa-utils` — `glxinfo`, to confirm 3D acceleration
- `policykit-1` — `pkexec`, so the GUI can ask for administrator rights

On Linux Mint:

```bash
sudo apt install smartmontools lm-sensors pciutils mesa-utils
sudo sensors-detect        # once, so temperatures are readable
```

**Optional**

- `zram-tools`, `earlyoom`, `tlp` — the application suggests these where they
  would help, but never installs anything by itself.

## Running with administrator rights

Reading SMART data, `dmidecode` and the system journal normally requires root.
Without it the application still runs and tells you exactly which evidence it
could not collect.

Three ways to get the complete picture:

```bash
sudo nexus-doctor --cli --scan --deep        # terminal, as root
nexus-doctor --gui                            # from a root shell
sudo -H nexus-doctor --gui                    # GUI as root (keeps $HOME sane)
```

In the graphical interface, administrator actions are requested through
`pkexec` at the moment they are needed; the interface itself never holds a root
shell.

## Files the application writes

- `/var/lib/nexus-system-doctor/backups/<session>/` — a copy of every
  configuration file a repair modified
- `~/.local/share/nexus-system-doctor/backups/<session>/` — the same, when
  running as an ordinary user
- `~/.local/share/nexus-system-doctor/` — the helper's log

It writes nothing else, and never outside those directories.

## Troubleshooting

**"Tkinter is not installed"** — `sudo apt install python3-tk`.

**The window does not start over SSH** — use the text interface:
`nexus-doctor --cli --scan`.

**SMART data missing even as root** — some USB enclosures and some firmware
block SMART passthrough. The application reports this rather than claiming the
disk is healthy. Try `sudo smartctl -a /dev/sda` to confirm.

**No temperatures reported** — run `sudo sensors-detect` once and reboot.

**Nothing appears in the menu** — run `update-desktop-database
/usr/share/applications`, or log out and back in.

**A repair reported "failed"** — that is the verification working: the command
ran, but the system did not end up in the intended state. The result pane shows
what was measured before and after. Nothing was damaged; the backup path is
listed if a file was touched.

## Verifying the download

```bash
dpkg-deb --info nexus-system-doctor_1.0.0_all.deb     # metadata
dpkg-deb --contents nexus-system-doctor_1.0.0_all.deb # every file it installs
python3 tests/run_tests.py                            # 67 tests
```
