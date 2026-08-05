# r2 corpus — `~/.local/share/radare2/`

Radare2 configuration, signatures, type definitions, and analysis profiles for
firmware reverse engineering. Deployed to `~/.local/share/radare2/` by `skel/install.sh`.

## Installation

```bash
# Symlink mode (default — writes back to repo on edit)
bash skel/install.sh

# One-shot copy
bash skel/install.sh --copy
```

---

## Quick Start by Target

### Linux (musl/uClibc firmware)
```r2
r2 -i ~/.local/share/radare2/profiles/linux-musl-arm64.r2 binary
aa; z/
```

### Windows PE
```r2
r2 -i ~/.local/share/radare2/profiles/windows-x64.r2 target.exe
aa; z/
```

### OpenWrt router binary
```r2
r2 -i ~/.local/share/radare2/profiles/openwrt-mips_24kc.r2 binary
aa; z/
```

### DJI flight controller
```r2
r2 -i ~/.local/share/radare2/profiles/dji-flyc.r2 m0306.bin
```

### Cisco IOS
```r2
r2 -i ~/.local/share/radare2/profiles/cisco-ios-mips32.r2 C1900-UN.BIN
```

### Cobham SAILOR / Intellian
```r2
r2 -i ~/.local/share/radare2/profiles/cobham-sailor-arm.r2 acu_ctl
r2 -i ~/.local/share/radare2/profiles/intellian-arm-glibc.r2 nxagent.cgi
```

### Firmware container identification
```r2
r2 -n firmware.bin
/m ~/.local/share/radare2/magic/firmware.magic
```

---

## Contents

### Magic Signatures (`magic/`)

| File | Coverage |
|------|---------|
| `firmware.magic` | **Universal**: DJI, Rockchip, TRX, SEAMA, Netgear, D-Link, JBOOT, LZ4, SquashFS LZMA, Cisco/Icom/VxWorks/Juniper stubs |
| `cisco_ios.magic` | Cisco IOS: monolithic ELF (MIPS/PPC), ZIP wrapper, IOS-XE, ROMMON, c1700 |
| `cobham_bgan.magic` | Cobham SATCOM: TIIF, BGAN .dl, MAIN_CPU, eCos ARM |
| `crypto_tables.magic` | Crypto tables: CRC-8/16/32, AES S-boxes, SHA-256/SHA-1, MD5, Blowfish, DES, ChaCha20, RC4 |
| `icom_firmware.magic` | Icom: IC-905 (AES), IC-705 (AES), IC-R8600 (LZSS), DU3, FIRM/AP-90M |
| `juniper_junos.magic` | Juniper: 55AA block-compressed ISO, domestic package ELF, metatags |
| `proto_fingerprint.magic` | Protocol handlers: HTTP, SNMP, MQTT, Modbus, SSH, SIP, RTSP, IKEv2, gRPC, SpaceX BwpProxy |
| `silabs_gbl.magic` | Silicon Labs GBL: Gecko Bootloader, D-Link Z-Wave OTA, Realtek Ameba |
| `starlink.magic` | SpaceX Starlink: sxverity container, gRPC APIs, UserClass enum, BwpProxy |
| `vxworks.magic` | VxWorks: kernel ELF (x86-64/ARM/AArch64), DKM, ROMFS, .wrs_build_vars, v5/v6 banner |

See `magic/README.md` for usage examples.

### Print Formats (`format/`)

Structure definitions for parsing firmware headers with `pf`:

| Format | Magic | Description |
|--------|-------|-------------|
| `pf.uimage_header` | 0x27051956 | U-Boot uImage (64 B, BE) |
| `pf.trx_header` | "HDR0" | Broadcom TRX (28 B, LE) |
| `pf.seama_header` | 0x5EA3A417 | SEAMA firmware |
| `pf.squashfs_super` | "hsqs"/"sqsh" | SquashFS v4 superblock |
| `pf.ubi_ec_header` | "UBI#" | UBI erase counter (BE) |
| `pf.jffs2_node` | 0x1985 | JFFS2 node header |
| `pf.cpio_newc` | "070701" | CPIO newc (110 B ASCII) |
| `pf.android_boot` | "ANDROID!" | Android boot image v0 |
| `pf.dji_xv4_header` | 0x12345678 | DJI xV4 package header |
| `pf.dji_xv4_entry` | — | DJI xV4 module entry |
| `pf.dji_imah_header` | "IM\*H" | DJI IM\*H signed module |
| `pf.dji_imah_chunk` | — | DJI IM\*H chunk header |
| `pf.dji_dupc55_hdr` | 0x55 | DJI DUPC 0x55 packet header |
| `pf.dji_dupc55_full` | — | DUPC full 13-byte header |
| `pf.dji_wifi_cmd_exec` | — | DUPC EXEC_COMMAND (RCE frame) |
| `pf.amba_a9_header` | — | Ambarella A9 main header |
| `pf.amba_part_header` | 0xA324EB90 | Ambarella partition |
| `pf.amba_romfs_header` | 0x66FC328A | Ambarella ROMFS |
| `pf.dji_flyc_param` | — | DJI FlyC parameter entry |

```r2
. ~/.local/share/radare2/format/firmware.pf
pf.uimage_header @ 0
pf.dji_imah_header @ 0
```

### Zignatures (`zigns/`)

| Directory | Coverage | Architectures |
|-----------|---------|---------------|
| `android/` | NDK r27c — Bionic libc, libm, libc++ | arm64-v8a, armeabi-v7a, x86_64, x86 |
| `cisco-ios/` | IOS 15.x MIPS32, IOS 12.3 PPC32 | MIPS32 BE, PPC32 BE |
| `debian/` | libc6, libssl, libcurl, libgnutls, libevent, libgcc, libbrotli, liblzma, libbz2, zlib, libmbedtls, libavformat, libavutil | amd64, arm64 |
| `dji/` | DJI SDK: DJIDevice, DJIUavService, libsdk_base, libwaes | arm64-v8a, armeabi-v7a |
| `embedded/` | Newlib: v6m, v7m, v7em, libm | arm-none-eabi (Cortex-M0/M3/M4/M7) |
| `glibc/` | GNU C library (Linaro toolchain builds) | armhf |
| `juniper/` | JunOS kmd 21.3R1.9 | x86-64 |
| `musl/` | musl libc (Alpine generic) | aarch64, arm, armhf, i386, x86_64, mips32-be/le |
| `openwrt/` | musl libc (OpenWrt ISA-specific) | mips_24kc, mipsel_24kc, mipsel_mips32, mips_mips32, mips64_octeonplus |
| `uclibc/` | uClibc-ng (Bootlin toolchains) | mips32, mips64, mips64-n32 |
| `vxworks/` | VxWorks 7 libraries: libc, libssl, libcrypto, libcurl, libz, sqlite3, libxml, cJSON, mosquitto | x86-64 |
| `windows/` | VC++ runtime VS2008–VS2022: vcruntime, ucrtbase, msvcp, concrt, vcamp, vcomp, mfc, atl | x64, x86, arm64 |
| `sessions/` | Per-binary corpus zsigs (12 confirmed binaries, 95–100% named) | mixed |

See `zigns/README.md` for full file listing and generation commands.

### Type Definitions (`types/`)

C headers loaded with `to <file>` then `aaft`:

| Directory | Target | Key Types |
|-----------|--------|-----------|
| `libc/` | POSIX | `linux_errno`, `linux_signal`, `sockaddr_in`, `stat`, `dirent`, open/mmap flags |
| `musl/` | musl libc | function signatures + zsig-name variants |
| `vxworks/` | VxWorks 7 | `STATUS`, `SEM_ID`, `TASK_ID`, task/semaphore/socket APIs |
| `android/` | Android | JNI, bionic, logcat, asset manager |
| `cobham/` | Cobham SATCOM | `tt_cshell_cmd`, ACU message structs, libfdloop session |
| `dji/` | DJI firmware | DUPC frames, FlyC params, IM\*H header, encrypt key blocks |
| `intellian/` | Intellian iARM | cJSON dispatch, UIF protocol, `bim_user_cfg`, escape_expand |
| `juniper/` | Juniper SRX | `dvpn_sa_entry_t`, `dvpn_token_entry_t` |
| `supermicro/` | Supermicro BMC | `tag_dispatch_entry`, IPMI session, `cgiGetPostVariable` |
| `spacex/` | Starlink | `UserClass` enum, BwpProxy types, unlock key structs |
| `windows/` | Windows PE | Win32 API, `SYSTEM_INFO`, NTSTATUS, WinError, VC++ zsig variants |
| `openssl/` | OpenSSL | libssl, libcrypto function signatures and structs |
| `ffmpeg/` | FFmpeg | libavcodec, libavformat, libavutil |
| `zlib/` | zlib | `z_stream`, `gz_header`, compression constants |
| `embedded/arm-none-eabi/` | Newlib Cortex-M | *Headers pending regeneration — use zsigs* |

See `types/README.md` for usage examples and enum lookup.

### Analysis Profiles (`profiles/`)

40+ pre-configured analysis scripts. See `profiles/README.md` for the full table.

Key profiles:

| Profile | Target |
|---------|--------|
| `windows-x64.r2` / `windows-x86.r2` / `windows-arm64.r2` | Windows PE |
| `android-arm64.r2` / `android-arm32.r2` | Android native |
| `linux-musl-arm64.r2` / `linux-musl-x64.r2` | Linux musl |
| `openwrt-mips_24kc.r2` (+ 4 variants) | OpenWrt routers |
| `cisco-ios-mips32.r2` / `cisco-ios-ppc32.r2` | Cisco IOS |
| `dji-flyc.r2` / `dji-amba-sys.r2` / `dji-wifi.r2` | DJI firmware |
| `vxworks7-x86_64.r2` | VxWorks 7 |
| `cobham-sailor-arm.r2` | Cobham SATCOM |
| `intellian-arm-glibc.r2` | Intellian VSAT |
| `supermicro-bmc-arm.r2` | Supermicro BMC |
| `juniper-srx.r2` | Juniper SRX |
| `spacex-starlink-musl-arm64.r2` | SpaceX Starlink |

### Address-Based Symbols (`symbols/`)

`.r2` scripts that apply confirmed function addresses from previous analysis sessions.
Named by vendor/product/version. Used when zsig matching fails on stripped binaries.

| Vendor | Files |
|--------|-------|
| `dji/` | 20+ scripts (flyc, gimbal, lightbridge, amba_sys, encode_usb, wifi, misc) |
| `juniper/` | kmd, dhcpd, HTTPD-GK, openflowd, JDHCPD + libssl.so |
| `spacex/` | emc_web_socket_server, libappmodules, user_mmut, user_terminal_frontend, uterm_binbox |
| `cisco/` | C1700-TP.BIN, C1900-UN.BIN |
| `raymarine/` | PlatformServicesDaemon, RemoteControlDaemon, racoon, raymarine.cgi-bin |
| `netgear/` | cm_diag, ipcTask |
| `autel/` | transmit, UpgradeService, libSecurity |
| `intellian/` | (in profiles) |
| `cobham/` | (in types) |
| `furuno/` | fursysmgr, libfurcommon |
| `icom/` | vxworks_kernel |
| `jrc/` | rmsd |
| `navico/` | rtspd |
| `dell/` | fcgi-auth, libdwebserver |
| `d-link/` | httpd |
| `paradigm/` | WebServer |

### Tools (`tool/`)

| Script | Purpose |
|--------|---------|
| `generate-zsig.py` | Generate zsigs from Linux .deb packages |
| `generate-musl-zsig.py` | Generate zsigs from musl libc source |
| `generate-openwrt-musl-zsig.py` | Generate zsigs from OpenWrt toolchain tarballs |
| `generate-ndk-zsig.py` | Generate zsigs from Android NDK |
| `generate-uclibc-mipsbe-zsig.py` | Generate zsigs from uClibc Bootlin toolchain |
| `generate-vcruntime-zsig.py` | Generate zsigs from VC++ runtime DLLs |
| `generate-winsdk-zsig.py` | Generate zsigs from Windows SDK static libs |
| `generate-vxworks-zsig.py` | Generate zsigs from VxWorks SDK libraries |
| `generate-juniper-zsig.py` | Generate zsigs from JunOS binaries |
| `generate-dji-symbols.py` | Generate r2 symbol scripts from DJI .map files |
| `generate-all-windows-zsigs.sh` | Batch all VS versions × architectures |
| `download-android-ndk.py` | Download NDK for a specific version |
| `download-musl.py` | Download and build musl from source |
| `download-openwrt-musl.py` | Download OpenWrt toolchain tarballs |
| `download-uclibc-mipsbe.py` | Download Bootlin uClibc toolchain |
| `download-vcredist.py` | Download VC++ redistributables (all versions) |
| `download-windows-sdk.py` | Download Windows SDK |
| `download-pdb.py` | Download PDB files from Microsoft symbol server |
| `prune-session-zsigs.py` | Remove low-quality session zsigs from corpus |
| `validate-corpus.py` | Validate zsig files and index.json consistency |
| `zsig_utils.py` | Shared utilities for zsig generation scripts |

### Documentation (`docs/`)

| File | Content |
|------|---------|
| `dji-firmware-formats.md` | DJI firmware container structure (xV4, IM\*H, Ambarella) |
| `dji-module-types.md` | DJI module type reference (target IDs, product codes) |
| `modality-firmware-workflows.md` | Modality (angr/Z3) symbolic execution workflows |
| `protocols/dji-dupc-0x55.md` | DJI DUPC 0x55 protocol specification |

---

## Common Workflows

### Firmware Container Identification
```r2
r2 -n firmware.bin
/m ~/.local/share/radare2/magic/firmware.magic
/m ~/.local/share/radare2/magic/vxworks.magic
```

### Library Function Identification
```r2
# Load matching zsigs for your target
zo ~/.local/share/radare2/zigns/musl/aarch64/musl-libc.zsig
aa; z/
# Matched functions show up as zign.*
afl~zign.
```

### Entropy Analysis (find encrypted/compressed regions)
```r2
p=e 256      # entropy graph
```

### Crypto Table Detection
```r2
/m ~/.local/share/radare2/magic/crypto_tables.magic
# Cross-reference a hit to find the algorithm's user:
axt @ hit0_0
```

### Protocol Attack Surface Mapping
```r2
/m ~/.local/share/radare2/magic/proto_fingerprint.magic
# Each hit = a protocol handler string. Cross-reference to find the handler:
axt @ hit0_0
```

### Struct Parsing After Magic Hit
```r2
. ~/.local/share/radare2/format/firmware.pf
/m ~/.local/share/radare2/magic/firmware.magic
s hit0_0
pf.uimage_header
```

---

## Architecture

```
~/.local/share/radare2/  (symlinks → /opt/aether/skel/.local/share/radare2/)
├── magic/           firmware format + crypto + protocol magic signatures
├── format/          pf print-format definitions (pf.uimage_header etc.)
├── types/           C headers: to <file> → aaft applies to imports
├── zigns/           function signatures: zo <file> → z/ to match
│   ├── sessions/    per-binary corpus (real dir, receives new zsigs)
│   └── ...
├── profiles/        analysis profiles: r2 -i <profile> binary
│   └── libc/        libc sub-profiles (musl, glibc, bionic, uclibc)
├── symbols/         address-based .r2 scripts per vendor/binary
├── scripts/         r2 automation scripts sourced by profiles
│   ├── windows-sinks.r2          sink labeler for Windows PE
│   ├── windows-sinks-stripped.r2 comment-stripped version (for embedding)
│   └── load-windows-sinks.r2     convenience wrapper
├── tool/            zsig + symbol generation scripts
├── docs/            protocol docs and firmware format specs
├── coverage.json    arch/vendor coverage matrix (profile+symbols+zsig status)
└── modality/        Modality (angr/Z3) symbolic execution bridge
```

---

## Philosophy

See [CONSTITUTION.md](CONSTITUTION.md):
- **Enhance r2** — don't wrap or replace r2 commands
- **Unix philosophy** — small tools that compose well
- **Firmware focus** — only what firmware RE needs
- **Simplicity** — if r2 already does it, don't duplicate
