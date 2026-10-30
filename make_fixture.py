#!/usr/bin/env python3
"""
Build the synthetic reference machine used by the test-suite.

The application has to work on a Lenovo IdeaPad S145-14AST that none of the
test environments physically resemble (the CI sandbox is a virtual machine with
no SMART-capable disk, no battery and no X session).  Rather than weakening the
checks, we build a complete fake machine: a sysroot containing the exact
``/proc`` and ``/sys`` layout of the target laptop, plus a ``commands.json``
describing what each diagnostic tool would print on it.

The engine cannot tell the difference between the real machine and this one,
because every read goes through ``nexus_doctor.core.executil``.

Run:  python3 tools/make_fixture.py [--out tests/fixtures/lenovo_s145]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
DEFAULT_OUT = HERE / "tests" / "fixtures" / "lenovo_s145"

# --------------------------------------------------------------------------
# The machine we are pretending to be
# --------------------------------------------------------------------------

CPU_MODEL = "AMD A6-9225 RADEON R4, 5 COMPUTE CORES 2C+3G"
DISK_MODEL = "ST1000LM035-1RK172"
KERNEL = "5.15.0-91-generic"


def write(root: Path, rel: str, content: str, mode: int | None = None) -> None:
    path = root / rel.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


# --------------------------------------------------------------------------
# /etc
# --------------------------------------------------------------------------

OS_RELEASE = """NAME="Linux Mint"
VERSION="21.3 (Virginia)"
ID=linuxmint
ID_LIKE="ubuntu debian"
PRETTY_NAME="Linux Mint 21.3"
VERSION_ID="21.3"
HOME_URL="https://www.linuxmint.com/"
SUPPORT_URL="https://forums.linuxmint.com/"
BUG_REPORT_URL="http://linuxmint-troubleshooting-guide.readthedocs.io/en/latest/"
PRIVACY_POLICY_URL="https://www.linuxmint.com/"
VERSION_CODENAME=virginia
UBUNTU_CODENAME=jammy
"""

FSTAB = """# /etc/fstab: static file system information.
UUID=8f2a1b3c-1111-4a2b-9c3d-0e1f2a3b4c5d /               ext4    errors=remount-ro 0       1
UUID=9c3d4e5f-2222-4b3c-8d4e-1f2a3b4c5d6e /home           ext4    defaults        0       2
/swapfile                                 none            swap    sw              0       0
"""

DEFAULT_KEYBOARD = """# KEYBOARD CONFIGURATION FILE
XKBMODEL="pc105"
XKBLAYOUT="in"
XKBVARIANT=""
XKBOPTIONS=""
BACKSPACE="guess"
"""

DEFAULT_LOCALE = """LANG="en_IN.UTF-8"
LANGUAGE="en_IN:en"
LC_NUMERIC="en_IN.UTF-8"
"""


# --------------------------------------------------------------------------
# /proc
# --------------------------------------------------------------------------

def meminfo() -> str:
    return """MemTotal:        3843848 kB
MemFree:          386520 kB
MemAvailable:     690216 kB
Buffers:           45212 kB
Cached:          1212444 kB
SwapCached:            0 kB
Active:          1684332 kB
Inactive:         954312 kB
Active(anon):    1223408 kB
Inactive(anon):   612044 kB
Active(file):     460924 kB
Inactive(file):   342268 kB
Unevictable:       32816 kB
Mlocked:           32816 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:            184220 kB
Writeback:         12044 kB
AnonPages:       1762332 kB
Mapped:           421056 kB
Shmem:            214400 kB
Slab:             288400 kB
SReclaimable:     142108 kB
SUnreclaim:       146292 kB
KernelStack:       16832 kB
PageTables:        62488 kB
CommitLimit:     1921924 kB
Committed_AS:    3512448 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       68932 kB
VmallocChunk:          0 kB
HardwareCorrupted:     0 kB
AnonHugePages:    204800 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
FileHugePages:         0 kB
FilePmdMapped:         0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:      318848 kB
DirectMap2M:     3608576 kB
"""


def cpuinfo() -> str:
    block = """processor\t: @N@
vendor_id\t: AuthenticAMD
cpu family\t: 21
model\t\t: 112
model name\t: CPU_MODEL_PLACEHOLDER
stepping\t: 0
microcode\t: 0x6000623
cpu MHz\t\t: 1000.000
cache size\t: 512 KB
physical id\t: 0
siblings\t: 2
core id\t\t: @N@
cpu cores\t: 2
apicid\t\t: @N@
initial apicid\t: @N@
fpu\t\t: yes
fpu_exception\t: yes
cpuid level\t: 13
wp\t\t: yes
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb hw_pstate ssbd vmmcall bmi1 xsaveopt arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif
bugs\t\t: sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass
bogomips\t: 5187.62
TLB size\t: 1536 4K pages
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate eff_freq_ro [13] [14]

"""
    out = ""
    for n in (0, 1):
        out += block.replace("@N@", str(n)).replace(
            "CPU_MODEL_PLACEHOLDER", CPU_MODEL)
    return out


MOUNTS = """sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
udev /dev devtmpfs rw,nosuid,relatime,size=1883024k,nr_inodes=470756,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=385084k,mode=755 0 0
/dev/sda2 / ext4 rw,relatime,errors=remount-ro 0 0
/dev/sda3 /home ext4 rw,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
tmpfs /run/user/1000 tmpfs rw,nosuid,nodev,relatime,size=385080k,mode=700,uid=1000,gid=1000 0 0
"""

INPUT_DEVICES = """I: Bus=0019 Vendor=0000 Product=0000 Version=0000
N: Name="Power Button"
P: Phys=PNP0C0C/button/input0
S: Sysfs=/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0C:00/input/input0
U: Uniq=
H: Handlers=kbd event0 
B: PROP=0
B: EV=3
B: KEY=10000000000000 0

I: Bus=0011 Vendor=0001 Product=0001 Version=ab83
N: Name="AT Translated Set 2 keyboard"
P: Phys=isa0060/serio0/input0
S: Sysfs=/devices/platform/i8042/serio0/input/input4
U: Uniq=
H: Handlers=sysrq kbd event4 leds 
B: PROP=0
B: EV=120013
B: KEY=402000000 3803078f800d001 feffffdfffefffff fffffffffffffffe
B: MSC=10
B: LED=7

I: Bus=0011 Vendor=0002 Product=0007 Version=01b1
N: Name="SynPS/2 Synaptics TouchPad"
P: Phys=isa0060/serio1/input0
S: Sysfs=/devices/platform/i8042/serio1/input/input8
U: Uniq=
H: Handlers=mouse0 event6 
B: PROP=5
B: EV=b
B: KEY=e520 10000 0 0 0 0
B: ABS=660800011000003

I: Bus=0003 Vendor=174f Product=116a Version=0100
N: Name="Lenovo EasyCamera: Lenovo EasyC"
P: Phys=usb-0000:00:12.0-1/button
S: Sysfs=/devices/pci0000:00/0000:00:12.0/usb1/1-1/1-1:1.0/input/input12
U: Uniq=
H: Handlers=kbd event10 
B: PROP=0
B: EV=3
B: KEY=100000 0 0 0 0

I: Bus=0019 Vendor=0000 Product=0006 Version=0000
N: Name="Video Bus"
P: Phys=LNXVIDEO/video/input0
S: Sysfs=/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/LNXVIDEO:00/input/input13
U: Uniq=
H: Handlers=kbd event11 
B: PROP=0
B: EV=3
B: KEY=3e000b00000000 0 0 0

I: Bus=0019 Vendor=17aa Product=5054 Version=4101
N: Name="Ideapad extra buttons"
P: Phys=ideapad/input0
S: Sysfs=/devices/pci0000:00/0000:00:14.3/PNP0C09:00/VPC2004:00/input/input14
U: Uniq=
H: Handlers=kbd rfkill event12 
B: PROP=0
B: EV=13
B: KEY=81000800100c03 4400000000300000 0 2
B: MSC=10
"""

MODULES = """amdgpu 10833920 22 - Live 0x0000000000000000
gpu_sched 49152 1 amdgpu, Live 0x0000000000000000
drm_buddy 20480 1 amdgpu, Live 0x0000000000000000
drm_ttm_helper 16384 1 amdgpu, Live 0x0000000000000000
ttm 86016 2 amdgpu,drm_ttm_helper, Live 0x0000000000000000
snd_hda_codec_realtek 151552 1 - Live 0x0000000000000000
snd_hda_codec_generic 98304 1 snd_hda_codec_realtek, Live 0x0000000000000000
ath9k 180224 0 - Live 0x0000000000000000
ath9k_common 32768 1 ath9k, Live 0x0000000000000000
ath9k_hw 487424 2 ath9k,ath9k_common, Live 0x0000000000000000
ath 36864 3 ath9k,ath9k_common,ath9k_hw, Live 0x0000000000000000
mac80211 1228800 1 ath9k, Live 0x0000000000000000
cfg80211 970752 4 ath9k,ath9k_common,ath9k,mac80211, Live 0x0000000000000000
kvm_amd 143360 0 - Live 0x0000000000000000
kvm 1114112 1 kvm_amd, Live 0x0000000000000000
btusb 61440 0 - Live 0x0000000000000000
btrtl 24576 1 btusb, Live 0x0000000000000000
btintel 45056 1 btusb, Live 0x0000000000000000
bluetooth 741376 5 btusb,btrtl,btintel, Live 0x0000000000000000
uvcvideo 122880 0 - Live 0x0000000000000000
videobuf2_vmalloc 20480 1 uvcvideo, Live 0x0000000000000000
sp5100_tco 20480 0 - Live 0x0000000000000000
k10temp 16384 0 - Live 0x0000000000000000
ccp 106496 1 kvm_amd, Live 0x0000000000000000
i2c_piix4 28672 0 - Live 0x0000000000000000
snd_hda_intel 57344 3 - Live 0x0000000000000000
ahci 45056 2 - Live 0x0000000000000000
libahci 45056 1 ahci, Live 0x0000000000000000
sd_mod 61440 3 - Live 0x0000000000000000
"""

SWAPS = "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n"


def proc_stat(base_total: int, base_io: int) -> str:
    idle = base_total
    return f"""cpu  {120000} 640 38000 {idle} {base_io} 4200 15800 0 0 0
cpu0 61000 320 19200 {idle // 2} {base_io // 2} 2100 7900 0 0 0
cpu1 59000 320 18800 {idle // 2} {base_io // 2} 2100 7900 0 0 0
intr 184729301 47 9 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
ctxt 402938475
btime 1698234001
processes 812344
procs_running 3
procs_blocked 2
softirq 129384756 1203 89345 234 10234 0 0 9234 0 0 238475
"""


# Fake process table: (pid, ppid, comm, cmdline, rss_pages, utime, stime)
PROCESSES = [
    (1, 0, "systemd", "/sbin/init splash", 2200, 4100, 3200),
    (418, 1, "systemd-journal", "/lib/systemd/systemd-journald", 3400, 900, 1500),
    (812, 1, "Xorg", "/usr/lib/xorg/Xorg :0 -seat seat0 -auth /var/run/lightdm/root/:0", 18500, 9100, 7200),
    (901, 1, "lightdm", "lightdm --session-child 13 20", 1400, 300, 200),
    (1050, 1, "ModemManager", "/usr/sbin/ModemManager --filter-policy=strict", 1600, 240, 190),
    (1060, 1, "bluetoothd", "/usr/lib/bluetooth/bluetoothd", 900, 60, 40),
    (1075, 1, "whoopsie", "whoopsie -f", 1200, 130, 90),
    (1100, 1, "tracker-miner-f", "/usr/libexec/tracker-miner-fs-3", 48000, 15200, 8400),
    (1104, 1, "tracker-extract", "/usr/libexec/tracker-extract-3", 26000, 4200, 2100),
    (1230, 1000, "xfce4-session", "xfce4-session", 3200, 480, 260),
    (1245, 1230, "xfwm4", "xfwm4 --display :0.0 --sm-client-id 2a1b", 6400, 2100, 1300),
    (1248, 1230, "xfce4-panel", "xfce4-panel --display :0.0 --sm-client-id 2a1c", 7200, 900, 600),
    (1300, 1230, "Thunar", "Thunar --daemon", 9800, 700, 420),
    (1500, 1230, "firefox", "/usr/lib/firefox/firefox -contentproc -isForBrowser", 168000, 44200, 12800),
    (1502, 1500, "Web Content", "/usr/lib/firefox/firefox -contentproc -isForBrowser", 121000, 21400, 7200),
    (1600, 1230, "xfce4-terminal", "xfce4-terminal", 5400, 320, 180),
]


# --------------------------------------------------------------------------
# /sys
# --------------------------------------------------------------------------

BAT0_UEVENT = """POWER_SUPPLY_NAME=BAT0
POWER_SUPPLY_TYPE=Battery
POWER_SUPPLY_STATUS=Discharging
POWER_SUPPLY_PRESENT=1
POWER_SUPPLY_TECHNOLOGY=Li-ion
POWER_SUPPLY_CYCLE_COUNT=612
POWER_SUPPLY_VOLTAGE_MIN_DESIGN=11400000
POWER_SUPPLY_VOLTAGE_NOW=10840000
POWER_SUPPLY_POWER_NOW=12400000
POWER_SUPPLY_ENERGY_FULL_DESIGN=37900000
POWER_SUPPLY_ENERGY_FULL=20100000
POWER_SUPPLY_ENERGY_NOW=7640000
POWER_SUPPLY_CAPACITY=38
POWER_SUPPLY_CAPACITY_LEVEL=Normal
POWER_SUPPLY_MODEL_NAME=L17M3PG1
POWER_SUPPLY_MANUFACTURER=SMP
POWER_SUPPLY_SERIAL_NUMBER=1234
"""

ADP_UEVENT = """POWER_SUPPLY_NAME=ADP0
POWER_SUPPLY_TYPE=Mains
POWER_SUPPLY_ONLINE=0
"""


# --------------------------------------------------------------------------
# Tool output fixtures
# --------------------------------------------------------------------------

SMARTCTL = """smartctl 7.2 2020-12-30 r5155 [x86_64-linux-5.15.0-91-generic] (local build)
Copyright (C) 2002-20, Bruce Allen, Christian Franke, www.smartmontools.org

=== START OF INFORMATION SECTION ===
Model Family:     Seagate Mobile HDD
Device Model:     ST1000LM035-1RK172
Serial Number:    WDE6QKJT
LU WWN Device Id: 5 000c50 0b4e8f3a1
Firmware Version: SDM1
User Capacity:    1,000,204,886,016 bytes [1.00 TB]
Sector Sizes:     512 bytes logical, 4096 bytes physical
Rotation Rate:    5400 rpm
Device is:        In smartctl database [for details use: -P show]
ATA Version is:   ACS-3 T13/2161-D revision 5
SATA Version is:  SATA 3.0, 6.0 Gb/s (current: 6.0 Gb/s)
Local Time is:    Wed Oct 28 14:02:11 2026 IST
SMART support is: Available - device has SMART capability.
SMART support is: Enabled

=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED
Please note the following marginal Attributes:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
190 Airflow_Temperature_Cel 0x0022   067   050   040    Old_age   Always       -       33 (Min/Max 22/41)

General SMART Values:
Offline data collection status:  (0x00)\tOffline data collection activity
\t\t\t\t\twas never started.

SMART Attributes Data Structure revision number: 10
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  1 Raw_Read_Error_Rate     0x000f   114   099   006    Pre-fail  Always       -       84123872
  3 Spin_Up_Time            0x0003   099   098   000    Pre-fail  Always       -       0
  4 Start_Stop_Count        0x0032   100   100   020    Old_age   Always       -       2841
  5 Reallocated_Sector_Ct   0x0033   082   082   010    Pre-fail  Always       -       328
  7 Seek_Error_Rate         0x000f   069   060   045    Pre-fail  Always       -       16782334
  9 Power_On_Hours          0x0032   075   075   000    Old_age   Always       -       21456
 10 Spin_Retry_Count        0x0013   100   100   097    Pre-fail  Always       -       0
 12 Power_Cycle_Count       0x0032   100   100   020    Old_age   Always       -       2503
184 End-to-End_Error        0x0032   100   100   099    Old_age   Always       -       0
187 Reported_Uncorrect      0x0032   001   001   000    Old_age   Always       -       412
188 Command_Timeout         0x0032   100   098   000    Old_age   Always       -       7
189 High_Fly_Writes         0x003a   100   100   000    Old_age   Always       -       0
190 Airflow_Temperature_Cel 0x0022   067   050   040    Old_age   Always       -       33 (Min/Max 22/41)
191 G-Sense_Error_Rate      0x0032   100   100   000    Old_age   Always       -       183
192 Power-Off_Retract_Count 0x0032   100   100   000    Old_age   Always       -       38
193 Load_Cycle_Count        0x0032   001   001   000    Old_age   Always       -       412883
194 Temperature_Celsius     0x0022   047   060   000    Old_age   Always       -       47 (Min/Max 20/55)
197 Current_Pending_Sector  0x0012   098   098   000    Old_age   Always       -       8
198 Offline_Uncorrectable   0x0010   098   098   000    Old_age   Offline      -       4
199 UDMA_CRC_Error_Count    0x003e   200   200   000    Old_age   Always       -       12
240 Head_Flying_Hours       0x0000   100   253   000    Old_age   Offline      -       19234
241 Total_LBAs_Written      0x0000   100   253   000    Old_age   Offline      -       4294836224
242 Total_LBAs_Read         0x0000   100   253   000    Old_age   Offline      -       9128374612

SMART Error Log Version: 1
ATA Error Count: 412
"""

SENSORS = """k10temp-pci-00c3
Adapter: PCI adapter
Tctl:         +83.0 C
Tdie:         +83.0 C

amdgpu-pci-0008
Adapter: PCI adapter
vddgfx:       +0.95 V
fan1:        3200 RPM
edge:         +78.0 C  (crit = +104.0 C, hyst = -273.1 C)

BAT0-acpi-0
Adapter: ACPI interface
in0:          10.84 V
"""

LSPCI = """00:00.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Stoney HT Configuration [1022:1576]
\tSubsystem: Lenovo Stoney HT Configuration [17aa:3802]
00:01.0 VGA compatible controller [0300]: Advanced Micro Devices, Inc. [AMD/ATI] Stoney [Radeon R2/R3/R4/R5 Graphics] [1002:98e4] (rev da)
\tSubsystem: Lenovo Stoney [Radeon R2/R3/R4/R5 Graphics] [17aa:3802]
\tKernel driver in use: amdgpu
\tKernel modules: amdgpu, radeon
00:01.1 Audio device [0403]: Advanced Micro Devices, Inc. [AMD/ATI] HDMI Audio [Radeon R4 Graphics] [1002:15b3]
\tSubsystem: Lenovo HDMI Audio [Radeon R4 Graphics] [17aa:3802]
\tKernel driver in use: snd_hda_intel
\tKernel modules: snd_hda_intel
00:02.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Stoney Northbridge [1022:157b]
00:08.0 Encryption controller [1080]: Advanced Micro Devices, Inc. [AMD] Stoney Platform Security Processor [1022:1578]
\tKernel driver in use: ccp
00:12.0 USB controller [0c03]: Advanced Micro Devices, Inc. [AMD] FCH USB EHCI Controller [1022:7908] (rev 39)
\tKernel driver in use: ehci-pci
02:00.0 Network controller [0280]: Qualcomm Atheros QCA9377 802.11ac Wireless Network Adapter [168c:0042] (rev 31)
\tSubsystem: Lenovo QCA9377 802.11ac Wireless Network Adapter [17aa:0901]
\tKernel driver in use: ath9k
\tKernel modules: ath9k
"""

GLXINFO = """name of display: :0
display: :0  screen: 0
direct rendering: Yes
Extended renderer info (GLX_MESA_query_renderer):
    Vendor: AMD (0x1002)
    Device: AMD Radeon(TM) R4 Graphics (STONEY, DRM 3.42.0, 5.15.0-91-generic, LLVM 13.0.1) (0x98e4)
    Version: 21.2.6
    Accelerated: yes
    Video memory: 512MB
    Unified memory: no
    Preferred profile: core (0x1)
    Max core profile version: 4.6
OpenGL vendor string: AMD
OpenGL renderer string: AMD Radeon(TM) R4 Graphics (STONEY, DRM 3.42.0, 5.15.0-91-generic, LLVM 13.0.1)
OpenGL core profile version string: 4.6 (Core Profile) Mesa 21.2.6
"""

XINPUT_LIST = """⎡ Virtual core pointer                    \tid=2\t[master pointer  (3)]
⎜   ↳ Virtual core XTEST pointer              \tid=4\t[slave  pointer  (2)]
⎜   ↳ SynPS/2 Synaptics TouchPad              \tid=11\t[slave  pointer  (2)]
⎣ Virtual core keyboard                   \tid=3\t[master keyboard (2)]
    ↳ Virtual core XTEST keyboard             \tid=5\t[slave  keyboard (3)]
    ↳ Power Button                            \tid=6\t[slave  keyboard (3)]
    ↳ Video Bus                               \tid=7\t[slave  keyboard (3)]
    ↳ Power Button                            \tid=8\t[slave  keyboard (3)]
    ↳ Ideapad extra buttons                   \tid=9\t[slave  keyboard (3)]
    ↳ AT Translated Set 2 keyboard            \tid=10\t[slave  keyboard (3)]
"""

XINPUT_PROPS = """Device 'AT Translated Set 2 keyboard':
\tDevice Enabled (140):\t1
\tCoordinate Transformation Matrix (142):\t1.000000, 0.000000, 0.000000, 0.000000, 1.000000, 0.000000, 0.000000, 0.000000, 1.000000
\tlibinput Send Events Modes Available (262):\t1, 0
\tlibinput Send Events Mode Enabled (263):\t0, 0
\tlibinput Send Events Mode Enabled Default (264):\t0, 0
"""

# key[50] = Shift_L, reported down in both samples -> stuck modifier.
XINPUT_STATE = """2 classes :
KeyClass
\tkey[0]=up
\tkey[20]=up
\tkey[37]=up
\tkey[50]=down
\tkey[64]=up
\tkey[65]=up
\tkey[66]=up
\tkey[133]=up
ButtonClass
\tbutton[1]=up
\tbutton[2]=up
\tbutton[3]=up
"""

SETXKBMAP = """rules:      evdev
model:      pc105
layout:     us
options:    terminate:ctrl_alt_bksp
"""

XSET_Q = """Keyboard Control:
  auto repeat:  on    key click percent:  0    LED mask:  00000000
  XKB indicators:
    00: Caps Lock:   off    01: Num Lock:    off    02: Scroll Lock: off
    03: Compose:     off    04: Kana:        off    05: Sleep:       off
  auto repeat delay:  660    repeat rate:  25
  auto repeating keys:  00ffffffdffffbbf
                        fadfffefffedffff
                        9fffffffffffffff
                        fff7ffffffffffff
  bell percent:  50    bell pitch:  400    bell duration:  100
Pointer Control:
  acceleration:  2/1    threshold:  4
Screen Saver:
  prefer blanking:  yes    allow exposures:  yes
  timeout:  600    cycle:  600
Colors:
  default colormap:  0x22    BlackPixel:  0x0    WhitePixel:  0xffffff
Font Path:
  catalogue:/etc/X11/fontpath.d,built-ins
DPMS (Energy Star):
  Standby: 600    Suspend: 600    Off: 600
  DPMS is Enabled
  Monitor is On
"""

KERNEL_LOG = """[ 7452.118032] EXT4-fs error (device sda2): ext4_find_entry:1536: inode #2621441: comm Thunar: reading directory lblock 0
[ 7452.118417] buffer I/O error on dev sda2, logical block 10485760, lost sync page write
[ 7461.902144] ata1.00: exception Emask 0x0 SAct 0x10 SErr 0x0 action 0x0
[ 7461.902151] ata1.00: irq_stat 0x40000008
[ 7461.902156] ata1.00: failed command: READ FPDMA QUEUED
[ 7461.902164] ata1.00: cmd 60/08:20:40:9e:5a/00:00:1f:00:00/40 tag 4 ncq 4096 in
[ 7461.902170] ata1.00: status: { DRDY ERR }
[ 7461.902175] ata1.00: error: { UNC }
[ 7462.410233] ata1: hard resetting link
[ 7462.732418] ata1: SATA link up 6.0 Gbps (SStatus 133 SControl 300)
[ 7480.551002] blk_update_request: I/O error, dev sda, sector 331882432 op 0x0:(READ) flags 0x80700 phys_seg 1 prio class 0
[ 9101.224118] Out of memory: Killed process 2233 (firefox) total-vm:2841224kB, anon-rss:1003524kB, file-rss:0kB, shmem-rss:2048kB, UID:1000 pgtables:4328kB oom_score_adj:0
[ 9101.310882] oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/user.slice/user-1000.slice/session-2.scope,task=firefox,pid=2233,uid=1000
[ 9203.441209] i8042: PNP: No PS/2 controller found
[ 9203.441233] atkbd serio0: Spurious ACK on isa0060/serio0. Some program might be trying to access hardware directly.
[ 9203.512884] atkbd serio0: Spurious ACK on isa0060/serio0. Some program might be trying to access hardware directly.
[12033.882144] microcode: CPU0: patch_level=0x06000623
[12033.882307] microcode: CPU1: patch_level=0x06000623
[12034.110882] amdgpu 0000:00:01.0: [drm] PCIE GART of 1024M enabled (table at 0x000000F400000000)
[12034.114882] amdgpu 0000:00:01.0: amdgpu: Trusted Memory Zone (TMZ) feature disabled as experimental (default)
[15402.771203] thermal thermal_zone0: critical temperature reached (95 C), shutting down
"""

JOURNAL_ERRORS = """Oct 28 13:02:11 ideapad-s145 kernel: ata1.00: failed command: READ FPDMA QUEUED
Oct 28 13:02:11 ideapad-s145 kernel: ata1.00: error: { UNC }
Oct 28 13:02:11 ideapad-s145 kernel: blk_update_request: I/O error, dev sda, sector 331882432 op 0x0:(READ) flags 0x80700
Oct 28 13:02:11 ideapad-s145 kernel: EXT4-fs error (device sda2): ext4_find_entry:1536: inode #2621441
Oct 28 13:02:12 ideapad-s145 kernel: buffer I/O error on dev sda2, logical block 10485760
Oct 28 13:04:02 ideapad-s145 kernel: Out of memory: Killed process 2233 (firefox)
Oct 28 13:04:02 ideapad-s145 kernel: oom-kill:constraint=CONSTRAINT_NONE,task=firefox,pid=2233
Oct 28 13:11:40 ideapad-s145 systemd[1]: Failed to start PackageKit Daemon.
Oct 28 13:11:40 ideapad-s145 systemd[1]: packagekit.service: Failed with result 'exit-code'.
Oct 28 13:12:02 ideapad-s145 systemd[1]: Failed to start Update Manager notifications.
Oct 28 13:14:18 ideapad-s145 kernel: amdgpu 0000:00:01.0: [drm] *ERROR* dc_dmub_srv_wait_idle: Error waiting for DMUB idle
Oct 28 13:14:19 ideapad-s145 kernel: amdgpu 0000:00:01.0: [drm] *ERROR* link_enc_cfg_validate: Invalid transcoder type
Oct 28 13:20:01 ideapad-s145 CRON[22991]: (CRON) error (grandchild #22992 failed with exit status 1)
Oct 28 13:31:44 ideapad-s145 tracker-miner-f[1100]: Error: SPARQL error: database disk image is malformed
Oct 28 13:31:44 ideapad-s145 tracker-miner-f[1100]: Error: SPARQL error: database disk image is malformed
Oct 28 13:35:02 ideapad-s145 kernel: usb 1-1: device descriptor read/64, error -110
Oct 28 13:41:18 ideapad-s145 systemd[1]: Failed to start Disk Manager.
Oct 28 13:41:18 ideapad-s145 systemd[1]: udisks2.service: Main process exited, code=exited, status=1/FAILURE
Oct 28 13:41:19 ideapad-s145 systemd[1]: udisks2.service: Start request repeated too quickly.
"""

SYSTEMD_FAILED = """● packagekit.service    loaded failed failed PackageKit Daemon
● udisks2.service       loaded failed failed Disk Manager
● update-notifier.service loaded failed failed Update Manager notifications

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state.
SUB    = The low-level unit activation state.
"""

BLAME = """42.331s apt-daily-upgrade.service
31.204s man-db.service
28.117s logrotate.service
21.442s fwupd.service
18.905s NetworkManager-wait-online.service
14.331s udisks2.service
11.204s e2scrub_all.service
9.882s ModemManager.service
7.441s accounts-daemon.service
6.203s systemd-journal-flush.service
"""

ANALYZE = """Startup finished in 6.2s (firmware) + 4.1s (loader) + 9.8s (kernel) + 58.3s (userspace) = 78.4s
graphical.target reached after 58.1s in userspace
"""

TUNE2FS = """tune2fs 1.46.5 (30-Dec-2021)
Filesystem volume name:   <none>
Last mounted on:          /
Filesystem UUID:          8f2a1b3c-1111-4a2b-9c3d-0e1f2a3b4c5d
Filesystem magic number:  0xEF53
Filesystem revision #:    1 (dynamic)
Filesystem features:      has_journal ext_attr resize_inode dir_index filetype needs_recovery extent 64bit flex_bg sparse_super large_file huge_file dir_nlink extra_isize metadata_csum
Filesystem flags:         signed_directory_hash
Default mount options:    user_xattr acl
Filesystem state:         clean with errors
Errors behavior:          Continue
Filesystem OS type:       Linux
Inode count:              61054976
Block count:              244190390
Reserved block count:     12209519
Free blocks:              17012647
Free inodes:              41230984
First block:              0
Block size:               4096
Fragment size:            4096
Blocks per group:         32768
Inodes per group:         8192
Last mount time:          Wed Oct 28 09:12:03 2026
Last write time:          Wed Oct 28 09:12:03 2026
Mount count:              34
Maximum mount count:      30
Last checked:             Sun Aug 14 21:02:11 2026
Check interval:           0 (<none>)
Lifetime writes:          4 TB
"""

MODINFO_ZRAM = """filename:       /lib/modules/5.15.0-91-generic/kernel/drivers/block/zram/zram.ko
description:    Compressed RAM block device driver
license:        Dual BSD/GPL
srcversion:     9A1D2B3C4E5F6A7B8C9D0E1
depends:        zsmalloc
intree:         Y
name:           zram
vermagic:       5.15.0-91-generic SMP mod_unload modversions
"""

DPKG_STATUS = """Package: xserver-xorg-input-libinput
Status: install ok installed
Priority: optional
Section: x11

Package: xserver-xorg-input-evdev
Status: install ok installed
Priority: optional
Section: x11

Package: smartmontools
Status: install ok installed
Priority: optional
Section: utils

Package: lm-sensors
Status: install ok installed
Priority: extra
Section: utils

Package: pciutils
Status: install ok installed
Priority: standard
Section: utils

Package: mesa-utils
Status: install ok installed
Priority: optional
Section: graphics

Package: x11-xserver-utils
Status: install ok installed
Priority: optional
Section: x11

Package: x11-xkb-utils
Status: install ok installed
Priority: optional
Section: x11

Package: xfce4
Status: install ok installed
Priority: optional
Section: x11

Package: tracker-miner-fs
Status: install ok installed
Priority: optional
Section: gnome

Package: firefox
Status: install ok installed
Priority: optional
Section: web

Package: linux-firmware
Status: install ok half-configured
Priority: optional
Section: kernel

Package: amd64-microcode
Status: install ok installed
Priority: optional
Section: kernel

Package: tlp
Status: deinstall ok config-files
Priority: optional
Section: utils

Package: earlyoom
Status: deinstall ok config-files
Priority: optional
Section: utils
"""

AUTOSTART_ENTRIES = [
    ("mintupdate", "Update Manager", "mintupdate-launcher"),
    ("mintreport", "System Reports", "mintreport-tray"),
    ("print-applet", "Print Queue Applet", "system-config-printer-applet"),
    ("blueman", "Bluetooth Manager", "blueman-applet"),
    ("nm-applet", "Network", "nm-applet"),
    ("light-locker", "Light Locker", "light-locker"),
    ("pulseaudio", "PulseAudio Sound System", "start-pulseaudio-x11"),
    ("at-spi-dbus-bus", "AT SPI D-Bus Bus", "/usr/lib/at-spi2-core/at-spi-bus-launcher --launch-immediately"),
    ("xfce4-power-manager", "Power Manager", "xfce4-power-manager"),
    ("update-notifier", "Update Notifier", "/usr/lib/update-notifier/update-notifier --startup-delay=60"),
]


def build(out: Path) -> None:
    root = out / "rootfs"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    # ---- /etc ---------------------------------------------------------
    write(root, "etc/os-release", OS_RELEASE)
    write(root, "etc/hostname", "ideapad-s145\n")
    write(root, "etc/fstab", FSTAB)
    write(root, "etc/default/keyboard", DEFAULT_KEYBOARD)
    write(root, "etc/default/locale", DEFAULT_LOCALE)
    write(root, "etc/lsb-release",
          'DISTRIB_ID=LinuxMint\nDISTRIB_RELEASE=21.3\nDISTRIB_CODENAME=virginia\n'
          'DISTRIB_DESCRIPTION="Linux Mint 21.3 Virginia"\n')

    # ---- /proc --------------------------------------------------------
    write(root, "proc/meminfo", meminfo())
    write(root, "proc/cpuinfo", cpuinfo())
    write(root, "proc/loadavg", "3.41 2.95 2.60 2/418 9123\n")
    write(root, "proc/uptime", "41822.55 162033.18\n")
    write(root, "proc/cmdline",
          "BOOT_IMAGE=/vmlinuz-5.15.0-91-generic root=UUID=8f2a1b3c-1111-4a2b-9c3d-0e1f2a3b4c5d "
          "ro quiet splash vt.handoff=7\n")
    write(root, "proc/swaps", SWAPS)
    write(root, "proc/modules", MODULES)
    write(root, "proc/mounts", MOUNTS)
    write(root, "proc/bus/input/devices", INPUT_DEVICES)
    # sysctl values that the tuning repairs read and write back
    write(root, "proc/sys/vm/swappiness", "60\n")
    write(root, "proc/sys/vm/vfs_cache_pressure", "100\n")
    write(root, "proc/sys/vm/dirty_ratio", "20\n")
    write(root, "proc/sys/vm/dirty_background_ratio", "10\n")
    write(root, "proc/sys/vm/dirty_bytes", "0\n")
    write(root, "proc/sys/vm/dirty_background_bytes", "0\n")
    write(root, "proc/sys/kernel/tainted", "0\n")
    write(root, "proc/1/comm", "systemd\n")

    for pid, ppid, comm, cmdline, rss, utime, stime in PROCESSES:
        fields = [str(ppid), "1", "1", "0", "-1", "4194560", "100000", "5000",
                  "1200", "800", str(utime), str(stime), "0", "0", "20", "0",
                  "5", "0", "1234567", "7654321", "123456", "0", "0"]
        write(root, f"proc/{pid}/stat",
              f"{pid} ({comm}) S " + " ".join(fields) + "\n")
        write(root, f"proc/{pid}/statm",
              f"{rss * 2} {rss} 800 12 0 900 0\n")
        write(root, f"proc/{pid}/cmdline", cmdline.replace(" ", "\0") + "\0")

    # ---- /sys ---------------------------------------------------------
    dmi = "sys/devices/virtual/dmi/id"
    write(root, f"{dmi}/sys_vendor", "LENOVO\n")
    write(root, f"{dmi}/product_name", "81ST\n")
    write(root, f"{dmi}/product_version", "IdeaPad S145-14AST\n")
    write(root, f"{dmi}/bios_version", "8SCN25WW\n")
    write(root, f"{dmi}/chassis_type", "Notebook\n")
    write(root, f"{dmi}/product_serial", "PF1XXXXX\n")
    write(root, f"{dmi}/board_name", "LNVNB161216\n")

    # 1 TB mechanical disk
    write(root, "sys/block/sda/queue/rotational", "1\n")
    write(root, "sys/block/sda/queue/scheduler", "[none] mq-deadline kyber bfq\n")
    write(root, "sys/block/sda/size", "1953525168\n")
    write(root, "sys/block/sda/device/model", DISK_MODEL + "\n")
    write(root, "sys/block/sda/device/vendor", "ATA     \n")
    write(root, "sys/block/sda/stat",
          "  912834  128374 4294836224 19283471  812374 1928341 9128374612 129384756 "
          "        2  8123471 148668227  128374 9128374 8123741\n")
    write(root, "sys/block/sda/removable", "0\n")
    write(root, "sys/block/sda2/size", "976771120\n")
    write(root, "sys/block/sda2/queue/rotational", "1\n")
    write(root, "sys/block/sda3/size", "976771072\n")
    write(root, "sys/block/sda3/queue/rotational", "1\n")

    # CPU frequency: stuck on powersave at 1.0 GHz of 2.6 GHz
    for cpu in ("cpu0", "cpu1"):
        base = f"sys/devices/system/cpu/{cpu}/cpufreq"
        write(root, f"{base}/scaling_governor", "powersave\n")
        write(root, f"{base}/scaling_driver", "acpi-cpufreq\n")
        write(root, f"{base}/scaling_cur_freq", "1000000\n")
        write(root, f"{base}/scaling_max_freq", "2600000\n")
        write(root, f"{base}/cpuinfo_max_freq", "2600000\n")
        write(root, f"{base}/cpuinfo_min_freq", "1300000\n")
        write(root, f"{base}/scaling_available_governors",
              "conservative ondemand userspace powersave performance schedutil\n")
        (root / f"sys/devices/system/cpu/{cpu}").mkdir(parents=True, exist_ok=True)

    # Thermal
    write(root, "sys/class/thermal/thermal_zone0/type", "acpitz\n")
    write(root, "sys/class/thermal/thermal_zone0/temp", "83000\n")
    write(root, "sys/class/thermal/thermal_zone0/policy", "step_wise\n")
    write(root, "sys/class/thermal/thermal_zone0/trip_point_0_temp", "95000\n")
    write(root, "sys/class/thermal/thermal_zone1/type", "x86_pkg_temp\n")
    write(root, "sys/class/thermal/thermal_zone1/temp", "84000\n")

    # Battery + AC
    write(root, "sys/class/power_supply/BAT0/uevent", BAT0_UEVENT)
    write(root, "sys/class/power_supply/ADP0/uevent", ADP_UEVENT)

    # DRM / GPU
    (root / "sys/class/drm/card0/device").mkdir(parents=True, exist_ok=True)
    (root / "sys/bus/pci/drivers/amdgpu").mkdir(parents=True, exist_ok=True)
    link = root / "sys/class/drm/card0/device/driver"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to("../../../../bus/pci/drivers/amdgpu")
    write(root, "sys/class/drm/card0/device/mem_info_vram_total", "536870912\n")
    write(root, "sys/class/drm/card0/device/mem_info_vram_used", "268435456\n")

    # Network interfaces (no wwan device -> ModemManager is surplus)
    write(root, "sys/class/net/lo/operstate", "unknown\n")
    write(root, "sys/class/net/wlp2s0/operstate", "up\n")

    write(root, "sys/module/zswap/parameters/enabled", "N\n")

    # CPU topology (dual core, no SMT) and GPU device nodes
    for cpu in ("cpu0", "cpu1"):
        write(root, f"sys/devices/system/cpu/{cpu}/topology/core_id", f"{cpu[-1]}\n")
        write(root, f"sys/devices/system/cpu/{cpu}/topology/physical_package_id", "0\n")
    write(root, "dev/dri/card0/.keep", "")
    write(root, "dev/dri/renderD128/.keep", "")

    # ---- user home ----------------------------------------------------
    home = root / "home/user"
    for name, disp, exec_line in AUTOSTART_ENTRIES:
        write(root, f"home/user/.config/autostart/{name}.desktop",
              "[Desktop Entry]\n"
              f"Name={disp}\n"
              f"Exec={exec_line}\n"
              "Terminal=false\n"
              "Type=Application\n"
              "X-GNOME-Autostart-enabled=true\n"
              "NoDisplay=false\n")
    write(root, "etc/xdg/autostart/at-spi-dbus-bus.desktop",
          "[Desktop Entry]\nType=Application\nName=AT SPI D-Bus Bus\n"
          "Exec=/usr/lib/at-spi2-core/at-spi-bus-launcher --launch-immediately\nNoDisplay=true\n")
    write(root, "etc/xdg/autostart/print-applet.desktop",
          "[Desktop Entry]\nName=Print Queue Applet\nExec=system-config-printer-applet\n"
          "Type=Application\nNoDisplay=false\n")

    # An X session must be detectable for the keyboard/graphics checks to run.
    write(root, "home/user/.Xauthority", "\x00\x00\x00\x00")
    (home / ".cache/thumbnails/normal").mkdir(parents=True, exist_ok=True)
    (home / ".local/share/Trash").mkdir(parents=True, exist_ok=True)
    (home / ".config").mkdir(parents=True, exist_ok=True)
    write(root, "var/log/journal/.keep", "")
    (root / "var/cache/apt/archives").mkdir(parents=True, exist_ok=True)
    (root / "var/lib/systemd/coredump").mkdir(parents=True, exist_ok=True)

    # ---- command fixtures --------------------------------------------
    tickers = {"proc/stat": [proc_stat(900000 + i * 1000, 20000 + i * 400)
                             for i in range(5)]}
    def pair(before, after):
        return {"before": before, "after": after}

    tickers["/proc/sys/vm/swappiness"] = pair("60\n", "10\n")
    tickers["/proc/sys/vm/vfs_cache_pressure"] = pair("100\n", "50\n")
    tickers["/proc/sys/vm/dirty_bytes"] = pair("0\n", "134217728\n")
    tickers["/proc/sys/vm/dirty_background_bytes"] = pair("0\n", "33554432\n")
    tickers["/proc/swaps"] = pair(
        SWAPS,
        "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n"
        "/dev/zram0\t\t\t\tpartition\t1921020\t0\t100\n")
    tickers["/proc/meminfo"] = pair(
        meminfo(),
        meminfo().replace("SwapTotal:             0 kB", "SwapTotal:       1921020 kB")
                  .replace("SwapFree:              0 kB", "SwapFree:        1921020 kB"))
    tickers["/sys/block/sda/queue/scheduler"] = pair(
        "[none] mq-deadline kyber bfq\n", "[bfq] none mq-deadline kyber\n")
    tickers["/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"] = pair(
        "powersave\n", "schedutil\n")
    tickers["/var/lib/dpkg/status"] = pair(
        DPKG_STATUS,
        DPKG_STATUS.replace("Status: install ok half-configured",
                            "Status: install ok installed"))
    tickers["/proc/mounts"] = pair(
        MOUNTS,
        MOUNTS.replace("rw,relatime,errors=remount-ro", "rw,noatime,errors=remount-ro")
              .replace(" /home ext4 rw,relatime ", " /home ext4 rw,noatime "))

    # The engine asks for the absolute path; register both forms.
    tickers["/proc/stat"] = tickers["proc/stat"]

    commands = [
        {"match": ["smartctl", "-H", "-i", "-A"], "rc": 0, "out": SMARTCTL},
        {"match": ["smartctl"], "rc": 0, "out": SMARTCTL},
        {"match": ["sensors"], "rc": 0, "out": SENSORS},
        {"match": ["lspci", "-k"], "rc": 0, "out": LSPCI},
        {"match": ["glxinfo", "-B"], "rc": 0, "out": GLXINFO},
        {"match": ["xinput", "list"], "rc": 0, "out": XINPUT_LIST},
        {"match": ["xinput", "list-props"], "rc": 0, "out": XINPUT_PROPS},
        {"match": ["xinput", "--query-state"], "rc": 0, "out": XINPUT_STATE},
        {"match": ["xfconf-query"], "contains": "use_compositing", "rc": 0,
         "before": {"out": "true\n"}, "after": {"out": "false\n"}},
        {"match": ["xfconf-query"], "rc": 0, "out": "false\n"},
        {"match": ["xfce4-panel", "--version"], "rc": 0, "out": "xfce4-panel 4.16.3 (Xfce 4.16)\n"},
        {"match": ["journalctl", "-k", "-b"], "rc": 0, "out": KERNEL_LOG},
        {"match": ["journalctl", "-p", "3", "-b"], "rc": 0, "out": JOURNAL_ERRORS},
        {"match": ["journalctl", "--disk-usage"], "rc": 0,
         "before": {"out": "Archived and active journals take up 1.4G in the file system.\n"},
         "after": {"out": "Archived and active journals take up 180.0M in the file system.\n"}},
        {"match": ["systemctl", "--failed"], "rc": 0, "out": SYSTEMD_FAILED},
        {"match": ["systemd-analyze", "blame"], "rc": 0, "out": BLAME},
        {"match": ["systemd-analyze"], "rc": 0, "out": ANALYZE},
        {"match": ["tune2fs", "-l"], "rc": 0, "out": TUNE2FS},
        {"match": ["modinfo", "zram"], "rc": 0, "out": MODINFO_ZRAM},
        {"match": ["dpkg", "--audit"], "rc": 0,
         "out": "The following packages are only half configured:\n linux-firmware\n"},
        {"match": ["systemctl", "list-units"], "rc": 0, "out": ""},

        # ---- commands issued by repairs -------------------------------
        {"match": ["modprobe"], "rc": 0, "out": ""},
        {"match": ["zramctl", "--find"], "rc": 0, "out": "/dev/zram0\n"},
        {"match": ["mkswap"], "rc": 0, "out": "Setting up swapspace version 1\n"},
        {"match": ["swapon"], "rc": 0, "out": ""},
        {"match": ["swapoff"], "rc": 0, "out": ""},
        {"match": ["sysctl", "-p"], "rc": 0, "out": ""},
        {"match": ["sysctl", "-w"], "rc": 0, "out": ""},
        {"match": ["udevadm"], "rc": 0, "out": ""},
        {"match": ["mount"], "rc": 0, "out": ""},
        {"match": ["apt-get", "clean"], "rc": 0, "out": ""},
        {"match": ["apt-get", "autoclean"], "rc": 0, "out": ""},
        {"match": ["apt-get", "install", "-f"], "rc": 0, "out": ""},
        {"match": ["dpkg", "--configure", "-a"], "rc": 0, "out": ""},
        {"match": ["journalctl", "--vacuum"], "rc": 0, "out": "Vacuuming done\n"},
        {"match": ["systemctl", "daemon-reload"], "rc": 0, "out": ""},
        {"match": ["systemctl", "is-enabled", "apt-daily.timer"], "rc": 0,
         "before": {"out": "enabled\n"}, "after": {"out": "disabled\n"}},
        {"match": ["systemctl", "is-enabled", "apt-daily-upgrade.timer"], "rc": 0,
         "before": {"out": "enabled\n"}, "after": {"out": "disabled\n"}},
        {"match": ["systemctl", "list-unit-files", "--type=timer"], "rc": 0,
         "out": "apt-daily.timer                       enabled\n"
                "apt-daily-upgrade.timer               enabled\n"
                "logrotate.timer                       enabled\n"
                "man-db.timer                          enabled\n"
                "fstrim.timer                          disabled\n"
                "e2scrub_all.timer                     disabled\n"
                "\n7 unit files listed.\n"},
        {"match": ["systemctl", "enable"], "rc": 0, "out": "Created symlink\n"},
        {"match": ["systemctl", "disable"], "rc": 0, "out": "Removed symlink\n"},
        {"match": ["systemctl", "restart"], "rc": 0, "out": ""},
        {"match": ["systemctl", "--user", "mask"], "rc": 0, "out": "Created symlink\n"},
        {"match": ["systemctl", "--user", "stop"], "rc": 0, "out": ""},
        {"match": ["systemctl", "is-enabled", "smartd"], "rc": 0,
         "before": {"out": "disabled\n"}, "after": {"out": "enabled\n"}},
        {"match": ["systemctl", "is-active"], "rc": 0,
         "before": {"out": "active\n"}, "after": {"out": "inactive\n"}},
        {"match": ["systemctl", "--user", "list-units"], "rc": 0,
         "before": {"out": "tracker-miner-fs-3.service loaded active running Tracker\n"
                           "tracker-extract-3.service loaded active running Tracker\n"},
         "after": {"out": ""}},
        {"match": ["xset", "r"], "rc": 0, "out": ""},
        {"match": ["xset", "q"], "rc": 0,
         "before": {"out": XSET_Q},
         "after": {"out": XSET_Q.replace("auto repeat delay:  660    repeat rate:  25",
                                         "auto repeat delay:  250    repeat rate:  35")}},
        {"match": ["setxkbmap", "-layout"], "rc": 0, "out": ""},
        {"match": ["setxkbmap", "-query"], "rc": 0,
         "before": {"out": SETXKBMAP},
         "after": {"out": SETXKBMAP.replace("layout:     us", "layout:     in")}},
        {"match": ["xfconf-query", "-c", "xfwm4"], "contains": "-s", "rc": 0, "out": ""},
        {"match": ["xfconf-query", "-c", "accessibility"], "rc": 0, "out": "false\n"},
    ]

    payload = {
        "_comment": (
            "Synthetic Lenovo IdeaPad S145-14AST (81ST) used by the Nexus System "
            "Doctor test-suite. Every value here is what the real tool or sysfs "
            "file would contain on that machine; the application cannot tell the "
            "difference because all reads go through core.executil."),
        "machine": {
            "vendor": "LENOVO", "product": "81ST",
            "version": "IdeaPad S145-14AST",
            "cpu": CPU_MODEL, "ram_mb": 3754, "disk": DISK_MODEL,
            "gpu": "AMD Stoney [Radeon R4 Graphics]", "kernel": KERNEL,
        },
        "tools": [
            "smartctl", "sensors", "lspci", "lsusb", "glxinfo", "xinput",
            "setxkbmap", "xset", "xfconf-query", "xfce4-panel", "systemd-analyze",
            "tune2fs", "modinfo", "journalctl", "systemctl", "dpkg", "apt-get",
            "zramctl", "swapon", "swapoff", "mkswap", "modprobe", "sysctl",
            "udevadm", "mount", "findmnt", "blkid", "mkdir", "rm", "cp", "tee",
            "chmod", "install", "mkdir",
        ],
        "uname": {"release": KERNEL, "version": "#101-Ubuntu SMP",
                  "machine": "x86_64"},
        "tickers": tickers,
        "statvfs": {
            "/": {"total": 984000000000, "avail": 68000000000,
                  "inodes_total": 61054976, "inodes_free": 41230984},
            "/home": {"total": 984000000000, "avail": 68000000000,
                      "inodes_total": 61054976, "inodes_free": 41230984},
        },
        "dir_sizes": {
            "/var/cache/apt/archives": {"before": 268435456, "after": 4194304},
            "/var/log": {"before": 210554880, "after": 52428800},
            "/home/user/.cache/thumbnails": {"before": 471859200, "after": 0},
            "/home/user/.local/share/Trash": 12582912,
            "/var/lib/systemd/coredump": 0,
            "/var/crash": 0,
        },
        "commands": commands,
    }
    (out / "commands.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Package database (read directly from the file, not via a command)
    write(root, "var/lib/dpkg/status", DPKG_STATUS)

    readme = (
        "Synthetic reference machine: Lenovo IdeaPad S145-14AST (81ST)\n"
        "============================================================\n\n"
        f"CPU      : {CPU_MODEL}\n"
        "RAM      : 3.7 GiB, no swap\n"
        f"Disk     : {DISK_MODEL} (1 TB, 5400 rpm, mechanical)\n"
        "GPU      : AMD Stoney [Radeon R4 Graphics], amdgpu driver\n"
        f"Kernel   : {KERNEL}\n"
        "Desktop  : Linux Mint 21.3 Xfce\n\n"
        "This is NOT a snapshot of a real machine. It is a hand-built fixture that\n"
        "reproduces the exact sysfs/proc layout and tool output of the target\n"
        "laptop so that every diagnostic code path can be tested offline and\n"
        "deterministically. It deliberately includes several real faults: bad\n"
        "sectors, ATA errors, OOM kills, a worn battery, thermal throttling, a\n"
        "stuck modifier key, the slow X11 key-repeat default, a running file\n"
        "indexer, failed services and a nearly full disk.\n\n"
        "Regenerate with:  python3 tools/make_fixture.py\n"
    )
    (out / "README.md").write_text(readme, encoding="utf-8")

    files = sum(1 for _ in root.rglob("*") if _.is_file())
    print(f"fixture written to {out}")
    print(f"  {files} files under rootfs/, "
          f"{len(commands)} command fixtures, "
          f"{len(payload['tools'])} declared tools")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="output directory")
    args = ap.parse_args()
    build(Path(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
