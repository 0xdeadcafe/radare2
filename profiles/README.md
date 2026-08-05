# Analysis Profiles

Pre-configured r2 scripts that set architecture, analysis options, type
definitions, and function signatures for a specific binary type.

## Quick Start

```bash
# Load when opening a binary
r2 -i ~/.local/share/radare2/profiles/linux-musl-arm64.r2 binary

# Or source from within r2
[0x00000000]> . ~/.local/share/radare2/profiles/windows-x64.r2
```

## Profile Index

### Windows PE

| Profile | Arch | Description |
|---------|------|-------------|
| `windows-x64.r2` | x86-64 | Windows PE x64 — loads VS2015–2022 vcruntime140, ucrtbase, msvcp140 zsigs |
| `windows-x86.r2` | x86 | Windows PE x86 — same runtimes, 32-bit |
| `windows-arm64.r2` | AArch64 | Windows PE ARM64 — VS2019/VS2022 vcruntime140, msvcp140 zsigs |

### Android Native

| Profile | Arch | Description |
|---------|------|-------------|
| `android-arm64.r2` | arm64-v8a | Android native lib/exe with NDK r27c bionic zsigs |
| `android-arm32.r2` | armeabi-v7a | 32-bit Android native with NDK r27c zsigs |

### Linux

| Profile | Arch | Description |
|---------|------|-------------|
| `linux-musl-x64.r2` | x86-64 | Linux/Alpine musl-libc — loads musl zsig + types |
| `linux-musl-x86.r2` | x86 | Linux musl x86 32-bit |
| `linux-musl-arm64.r2` | aarch64 | Linux/Alpine musl-libc for ARM64 |
| `linux-musl-arm32.r2` | ARM32 | Linux musl ARM32 hard-float (Cortex-A) |
| `linux-musl-armv7.r2` | ARMv7 | Linux musl ARMv7 (armv7l, Thumb-2) |
| `linux-glibc-arm32.r2` | ARM32 | Linux glibc ARM32 hard-float (Linaro toolchain) |
| `linux-uclibc-mips.r2` | MIPS32 BE | Embedded Linux uClibc — generic MIPS big-endian |
| `mips-plt-resolve.r2` | MIPS32 | PLT→GOT resolver helper for stripped MIPS binaries |

### OpenWrt Router Firmware

| Profile | CPU Target | Description |
|---------|-----------|-------------|
| `openwrt-mips_24kc.r2` | MIPS 24Kc | Atheros AR9xxx — TP-Link WR841N, GL-AR150 |
| `openwrt-mipsel_24kc.r2` | MIPSel 24Kc | MediaTek MT7621 — Xiaomi MiWiFi 3, ASUS RT-N56U |
| `openwrt-mipsel_mips32.r2` | MIPSel MIPS32r1 | Broadcom BCM47xx — Linksys WRT54G, Netgear WGR614 |
| `openwrt-mips_mips32.r2` | MIPS MIPS32r1 | BCM63xx DSL — Livebox 2, BT HH3 |
| `openwrt-mips64_octeonplus.r2` | MIPS64 OcteonPlus | Ubiquiti EdgeRouter Lite/4, Cavium Octeon |

### Cisco IOS

| Profile | Arch | Description |
|---------|------|-------------|
| `cisco-ios-mips.r2` | MIPS32 BE | IOS C1900/C2900/C3900 (e_machine=0xC0) — auto-selects version |
| `cisco-ios-mips32.r2` | MIPS32 BE | IOS C1900 ISR — 15.x monolithic binary |
| `cisco-ios-ppc32.r2` | PPC32 BE | IOS C1700 — PAGENT binary (e_machine=0x33) |

### DJI Drone Firmware

| Profile | CPU | Description |
|---------|-----|-------------|
| `dji-flyc.r2` | STM32F4 (Cortex-M4) | Flight Controller m0306 — Phantom 3/4, Mavic, Spark |
| `dji-gimbal.r2` | STM32F103 (Cortex-M3) | Gimbal controller |
| `dji-amba-sys.r2` | Ambarella A9 (Cortex-A9) | Camera system partition (`sys` binary) |
| `dji-lightbridge.r2` | STM32F103 (Cortex-M3) | Lightbridge / OFDM MCU |
| `dji-encode.r2` | TI DM368 (ARM926) | Video encoder / encode_usb |
| `dji-generic.r2` | ARM32 | Generic / unknown DJI ARM module |
| `dji-wifi.r2` | ARM32 | Wi-Fi module (m0700, m2700) — DUPC 0x55 protocol |
| `dji-commands.r2` | — | Command/enum reference script (flag constants, protocol IDs) |
| `dji-android-arm32.r2` | armeabi-v7a | DJI Android SDK native — libdji*.so (armeabi-v7a) |
| `dji-fly-android-arm64.r2` | arm64-v8a | DJI Fly app Android native — arm64-v8a |
| `dji-assistant-win32.r2` | x86 | DJI Assistant 2 Windows PE32 |

### VxWorks

| Profile | Arch | Description |
|---------|------|-------------|
| `vxworks7-x86_64.r2` | x86-64 | VxWorks 7 kernel image (Intel BSP, locore@0x408000) — loads VxWorks 7 zsigs |
| `icom-vxworks-mips.r2` | MIPS32 BE | Icom VxWorks MIPS — generic VxWorks MIPS firmware |
| `icom-ap90m-vxworks.r2` | MIPS32 BE | Icom AP-90M (FIRM container, VxWorks 6.9 MIPS32 BE) |

### Maritime / SATCOM

| Profile | Arch | Description |
|---------|------|-------------|
| `cobham-sailor-arm.r2` | ARM32 LE | Cobham SAILOR GX / Explorer (ACU acu_ctl, acu_vmu, suu) — loads tt_cshell types |
| `cobham-e710-api.r2` | ARM32 LE | Cobham Explorer 710 API service |
| `cobham-e710-pam.r2` | ARM32 LE | Cobham Explorer 710 PAM daemon |
| `cobham-e500-mips.r2` | MIPS32 | Cobham Explorer 500 (older MIPS platform) |
| `viasat-explorer-gx-arm.r2` | ARM32 LE | Viasat / Cobham Explorer GX family |
| `intellian-arm-glibc.r2` | ARM32 LE | Intellian iARM-GX / iARM-nx (JRC JUE-100GX, Viasat GX) — nxagent.cgi, acu_server, libcommon.so |
| `furuno-felcom-arm.r2` | ARM32 LE | Furuno FELCOM maritime SATCOM terminal |

### SpaceX Starlink

| Profile | Arch | Description |
|---------|------|-------------|
| `spacex-starlink-musl-arm64.r2` | AArch64 | Starlink catson/catapult user terminal — musl ARM64, loads Starlink zsigs + proto fingerprints |

### Network Appliances

| Profile | Arch | Description |
|---------|------|-------------|
| `juniper-srx.r2` | x86-64 / MIPS64 | Juniper SRX JunOS — loads JunOS kmd zsigs + DVPN types |
| `supermicro-bmc-arm.r2` | ARM32 | Supermicro BMC (B2SC1-CPU) — ipmi.cgi, url_redirect.cgi, CGI tag dispatch |
| `hpe-ilo7-arm64.r2` | AArch64 | HPE iLO 7 BMC ARM64 |
| `bosch-cpp3.r2` | ARM32 LE | Bosch VIP X CPP3 — ARM32 statically linked RTOS modules (arm.app1, webservice.dll, rtsp.dll) |
| `bosch-cppenc.r2` | ARM32 Thumb | Bosch VIP X CPP-ENC — ARM Thumb-2 raw flat binary (base 0x80000000; container key 0x42) |
| `netgear-orbi-cgi.r2` | ARM32 Thumb | NETGEAR Orbi RBR50 net-cgi — ARM32 Thumb PIE .so; musl zsigs; r2 base=0x0, angr base=0x400000 |
| `autel-aarch64.r2` | AArch64 | Autel EVO 2 — AArch64 Linux (transmit, UpgradeService) |

### libc Sub-profiles (shared by vendor profiles)

Located in `libc/` — these are included by the above profiles, not loaded directly:

| File | Contents |
|------|---------|
| `libc/glibc-arm32.r2` | glibc ARM32 zsigs |
| `libc/glibc-arm64.r2` | glibc ARM64 zsigs |
| `libc/glibc-x64.r2` | glibc x86-64 zsigs |
| `libc/bionic-arm32.r2` | Android Bionic ARM32 |
| `libc/bionic-arm64.r2` | Android Bionic ARM64 |
| `libc/musl-arm32.r2` | musl ARM32 |
| `libc/musl-arm64.r2` | musl ARM64 |
| `libc/musl-mips32-be.r2` | musl MIPS32 BE |
| `libc/musl-mips32-le.r2` | musl MIPS32 LE |
| `libc/musl-x64.r2` | musl x86-64 |
| `libc/musl-x86.r2` | musl x86 |
| `libc/uclibc-arm32.r2` | uClibc ARM32 |
| `libc/uclibc-mips32.r2` | uClibc MIPS32 BE |
| `libc/uclibc-mips64.r2` | uClibc MIPS64 |
| `libc/uclibc-mips64-n32.r2` | uClibc MIPS64 N32 ABI |

## What Each Profile Configures

1. **Architecture** — `e asm.arch`, `e asm.bits`, `e cfg.bigendian`, `e asm.cpu`
2. **Analysis options** — jump tables, indirect branches, string analysis, demangle
3. **Type definitions** — `to` commands loading vendor and libc C headers
4. **Zignatures** — `zo` commands loading function signature files
5. **Magic scans** — `/m` to scan for crypto tables and protocol fingerprints
6. **Visual settings** — comment column, description overlay
7. **Known symbols** — `f` commands pinning confirmed addresses from previous sessions
8. **Attack surface echo** — key sinks, dispatch tables, default credentials

## Workflow

```bash
# 1. Identify binary
rabin2 -I binary
file binary

# 2. Choose and load profile
r2 -i ~/.local/share/radare2/profiles/linux-musl-arm64.r2 binary

# 3. Analyse
[0x0]> aa         # standard analysis
[0x0]> z/         # match loaded zignatures against functions

# 4. Find dangerous sinks quickly
[0x0]> axt @ sym.imp.system
[0x0]> axt @ sym.imp.popen
[0x0]> axt @ sym.imp.sprintf

# 5. Load additional magic
[0x0]> /m ~/.local/share/radare2/magic/crypto_tables.magic
[0x0]> /m ~/.local/share/radare2/magic/proto_fingerprint.magic
```

## Creating a Custom Profile

Copy the closest existing profile:

```bash
cp ~/.local/share/radare2/profiles/linux-musl-arm64.r2 \
   /opt/aether/skel/.local/share/radare2/profiles/my-target.r2
```

Adjust:
- `e asm.arch` / `e asm.bits` / `e cfg.bigendian`
- `zo` lines to load matching zsig files
- `to` lines to load matching type headers
- Add vendor-specific `f sym.*` flags from previous sessions
- Add `echo` lines summarising attack surface

## Auto-Selection via `aether_r2profile.py`

The `scripts/aether_r2profile.py` script maps `(arch, bits, vendor)` tuples to
profiles automatically during AETHER binary triage. It loads:
- the arch/vendor profile
- the matching libc sub-profile when the ELF interpreter identifies musl/uClibc/glibc/bionic
- session zsigs from the shared corpus

It also performs arch-specific PLT resolution where needed (for example AArch64
and MIPS helper flows). Signature application/matching behavior should be treated
as workflow-dependent; do not assume every loader path automatically performs a
manual-equivalent `z/`.
