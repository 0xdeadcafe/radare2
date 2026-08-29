# r2 corpus — `~/.local/share/radare2/`

Radare2 configuration, signatures, type definitions, and analysis profiles for
binary reverse engineering across firmware, desktop/server, mobile, and embedded
targets. Deployed to `~/.local/share/radare2/` by `skel/install.sh`.

## Installation

```bash
# Symlink mode (default — writes back to repo on edit)
bash skel/install.sh

# One-shot copy
bash skel/install.sh --copy
```

Zsig tiers are defined in `zigns/tiers.json`. The `core` tier (~46 MB) is
required; `vendor` (~96 MB), `debian-large` (347 MB), and `windows-large`
(349 MB) are optional and presence-checked at runtime by `check_r2_corpus.sh`.

---

## Quick Start by Target

### Linux — musl / uClibc / glibc (auto-profile)
```r2
# aether_r2profile.py selects the right profile automatically via r2_open()
# Manual override:
r2 -i ~/.local/share/radare2/profiles/linux-musl-arm64.r2  binary
r2 -i ~/.local/share/radare2/profiles/linux-glibc-arm32.r2 binary
r2 -i ~/.local/share/radare2/profiles/linux-uclibc-arm32.r2 binary
aa; z/
```

### Windows PE
```r2
r2 -i ~/.local/share/radare2/profiles/windows-x64.r2 target.exe
aa; z/
```

### macOS Mach-O
```r2
r2 -i ~/.local/share/radare2/profiles/macos-arm64.r2 target          # Apple Silicon
r2 -i ~/.local/share/radare2/profiles/macos-x64.r2   target          # Intel
aa; z/
```

### Android native library
```r2
r2 -i ~/.local/share/radare2/profiles/android-arm64.r2 libtarget.so
aa; z/
```

### OpenWrt router binary
```r2
r2 -i ~/.local/share/radare2/profiles/openwrt-mips_24kc.r2 binary
aa; z/
```

### Go binary
```r2
r2 -i ~/.local/share/radare2/profiles/linux-go-amd64.r2 binary
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

### Container / format identification
```r2
r2 -n sample.bin
/m ~/.local/share/radare2/magic/firmware.magic
```

---

## Contents

### Magic Signatures (`magic/`)

| File | Coverage |
|------|---------|
| `firmware.magic` | Composite container coverage: DJI, Rockchip, TRX, SEAMA, Netgear, D-Link, JBOOT, LZ4, SquashFS LZMA, Cisco/Icom/VxWorks/Juniper stubs |
| `cisco_ios.magic` | Cisco IOS: monolithic ELF (MIPS/PPC), ZIP wrapper, IOS-XE, ROMMON, c1700 |
| `cobham_bgan.magic` | Cobham SATCOM: TIIF, BGAN .dl, MAIN_CPU, eCos ARM |
| `crypto_tables.magic` | Crypto tables: CRC-8/16/32, AES S-boxes, SHA-256/SHA-1, MD5, Blowfish, DES, ChaCha20, RC4, SM4, Camellia, ARIA, Curve25519, Poly1305, HMAC |
| `icom_firmware.magic` | Icom: IC-905 (AES), IC-705 (AES), IC-R8600 (LZSS), DU3, FIRM/AP-90M |
| `juniper_junos.magic` | Juniper: 55AA block-compressed ISO, domestic package ELF, metatags |
| `proto_fingerprint.magic` | Protocol handlers: HTTP, SNMP, MQTT, Modbus, SSH, SIP, RTSP, IKEv2, gRPC, SpaceX BwpProxy, DNP3, IEC-60870, IEC-61850, BACnet, EtherCAT, PROFINET, OPC UA, Zigbee, Z-Wave, Matter, WebSocket, WireGuard, NETCONF, gNMI |
| `silabs_gbl.magic` | Silicon Labs GBL: Gecko Bootloader, D-Link Z-Wave OTA, Realtek Ameba |
| `starlink.magic` | SpaceX Starlink: sxverity container, gRPC APIs, UserClass enum, BwpProxy |
| `uefi.magic` | UEFI: EFI PE32+ executables, Firmware Volumes (FV/FFS), capsule updates, NvRam variable store, Intel Flash Descriptor, ME firmware, ACPI tables, Secure Boot databases |
| `vxworks.magic` | VxWorks: kernel ELF (x86-64/ARM/AArch64), DKM, ROMFS, .wrs_build_vars, v5/v6 banner |

See `magic/README.md` for usage examples.

### Print Formats (`format/`)

Structure definitions for parsing binary/container headers with `pf`:

| Format | Magic | Description |
|--------|-------|-------------|
| `pf.uimage_header` | 0x27051956 | U-Boot uImage (64 B, BE) |
| `pf.trx_header` | "HDR0" | Broadcom TRX (28 B, LE) |
| `pf.seama_header` | 0x5EA3A417 | SEAMA image |
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

Tier layout defined in `zigns/tiers.json`. Regenerate any tier with the corresponding
`tool/generate-*.py` script.

| Directory | Coverage | Architectures | Tier |
|-----------|---------|---------------|------|
| `android/` | NDK r27c — Bionic libc, libm, libc++ | arm64-v8a, armeabi-v7a, x86\_64, x86 | vendor |
| `cisco-ios/` | IOS 15.x MIPS32, IOS 12.3 PPC32 | MIPS32 BE, PPC32 BE | vendor |
| `debian/` | libc6, libssl, libcrypto, libcurl, libgnutls, libevent, libgcc, libstdc++, zlib, libbz2, liblzma, libbrotli, libmbedtls, libzstd, liblz4, libprotobuf, libxml2, libsnappy, libsqlite3, libsodium, libpcre2, libavformat, libavutil (23 libs × 4 arches = 91 zsigs) | amd64, arm64, armhf, i386 | debian-large |
| `dji/` | DJI SDK: DJIDevice, DJIUavService, libsdk\_base, libwaes | arm64-v8a, armeabi-v7a | vendor |
| `embedded/` | FreeRTOS kernel (Cortex-M0/M3/M4/M7); Newlib libc+libm (v6m, v7m, v7em) | arm-none-eabi | core |
| `go/` | Go 1.23 standard library | amd64, arm64, x86 | vendor |
| `juniper/` | JunOS kmd 21.3R1.9 | x86-64 | vendor |
| `macos/` | Apple libSystem (C runtime) + libm — compiled from Apple open source (Libc-1752, Libm-2026) via `clang --target=<arch>-apple-macos` + macOS 15.4 SDK | arm64, x86\_64 | vendor |
| `musl/` | musl libc | aarch64, armhf, armv7, ppc64le, riscv64, s390x, x86, x86\_64 | core |
| `openwrt/` | musl libc (OpenWrt ISA-specific builds) | mips\_24kc, mipsel\_24kc, mipsel\_mips32, mips\_mips32, mips64\_octeonplus | core |
| `uclibc/` | uClibc-ng (Bootlin toolchains) | mips32, mips64, mips64-n32, arm32 (armv5-eabi), arm64 | core |
| `vxworks/` | VxWorks 7 libraries: libc, libssl, libcrypto, libcurl, libz, sqlite3, libxml, cJSON, mosquitto | x86-64 | vendor |
| `windows/` | VC++ runtime VS2008–VS2022: vcruntime, ucrtbase, msvcp, concrt, vcamp, vcomp, mfc, atl | x64, x86, arm64 | windows-large |
| `sessions/` | Per-binary corpus zsigs (7 sessions, 100% named; 1 archived at 0%) | mixed | — (always local) |

> **`glibc/`** — previously held a Linaro-toolchain ARM32 glibc zsig; superseded by
> `debian/armhf/libc6.zsig` (higher quality, full library set). Directory retained
> for backwards-compat symlinks; contains no zsigs.

See `zigns/README.md` for the full per-file listing and generation commands.

### Type Definitions (`types/`)

C headers loaded with `to <file>` then `aaft`:

| Directory | Target | Key Types |
|-----------|--------|-----------|
| `libc/` | POSIX | `linux_errno`, `linux_signal`, `sockaddr_in`, `stat`, `dirent`, open/mmap flags |
| `libc/fcntl-arm32.h` | ARM32 Linux | ARM32-correct `struct stat` (120 bytes), `struct dirent` |
| `musl/` | musl libc | function signatures + zsig-name variants |
| `vxworks/` | VxWorks 7 | `STATUS`, `SEM_ID`, `TASK_ID`, task/semaphore/socket APIs |
| `android/` | Android | JNI, bionic, logcat, asset manager |
| `cobham/` | Cobham SATCOM | `tt_cshell_cmd`, ACU message structs, libfdloop session |
| `dji/` | DJI platforms | DUPC frames, FlyC params, IM\*H header, encrypt key blocks |
| `intellian/` | Intellian iARM | cJSON dispatch, UIF protocol, `bim_user_cfg`, escape_expand |
| `juniper/` | Juniper SRX | `dvpn_sa_entry_t`, `dvpn_token_entry_t` |
| `supermicro/` | Supermicro BMC | `tag_dispatch_entry`, IPMI session, `cgiGetPostVariable` |
| `spacex/` | Starlink | `UserClass` enum, BwpProxy types, unlock key structs |
| `windows/` | Windows PE | Win32 API, `SYSTEM_INFO`, NTSTATUS, WinError, VC++ zsig variants |
| `openssl/` | OpenSSL | libssl, libcrypto function signatures and structs |
| `ffmpeg/` | FFmpeg | libavcodec, libavformat, libavutil |
| `zlib/` | zlib | `z_stream`, `gz_header`, compression constants |
| `mbedtls/` | Mbed TLS | `mbedtls_ssl_context/config`, AES/SHA/MD5/PK contexts, cipher/hash enums |
| `lua/` | Lua 5.x | Full C API (`lua_State`, `lua_pcall`, `luaL_*`), `lua_Debug`, type/status enums |
| `freebsd/` | FreeBSD | `kevent`, kqueue, Capsicum (`cap_enter`), jail, BSD `struct stat` |
| `embedded/arm-none-eabi/` | Cortex-M | NVIC, SCB, SysTick, MPU, DWT, CoreDebug, FPU registers; CMSIS API |

See `types/README.md` for usage examples and enum lookup.

### Analysis Profiles (`profiles/`)

65+ pre-configured analysis scripts. Auto-profile selection via `aether_r2profile.py`
reads `profiles_config.json` and picks the right profile from arch, vendor, and
interpreter hints. See `profiles/README.md` for the full table and routing schema.

**Linux / embedded:**

| Profile | Target |
|---------|--------|
| `linux-musl-arm64.r2` / `linux-musl-x64.r2` | Linux musl (arm64, x86-64) |
| `linux-musl-arm32.r2` / `linux-musl-armv7.r2` | Linux musl (arm32) |
| `linux-musl-x86.r2` / `linux-musl-ppc64le.r2` / `linux-musl-riscv64.r2` / `linux-musl-s390x.r2` | Linux musl (other arches) |
| `linux-glibc-x64.r2` / `linux-glibc-arm64.r2` | Linux glibc (Debian/Ubuntu/RHEL, server, CTF) |
| `linux-glibc-arm32.r2` / `linux-glibc-x86.r2` | Linux glibc (ARM32, i386) |
| `linux-uclibc-arm32.r2` / `linux-uclibc-mips.r2` | Linux uClibc |
| `linux-go-amd64.r2` / `linux-go-arm64.r2` / `linux-go-x86.r2` | Go binaries |
| `openwrt-mips_24kc.r2` (+ 4 variants) | OpenWrt routers |
| `freebsd-x64.r2` | FreeBSD x86-64 (JunOS userland, pfSense, TrueNAS) |

**Desktop / mobile:**

| Profile | Target |
|---------|--------|
| `windows-x64.r2` / `windows-x86.r2` / `windows-arm64.r2` | Windows PE |
| `macos-arm64.r2` / `macos-x64.r2` | macOS Apple Silicon / Intel |
| `android-arm64.r2` / `android-arm32.r2` / `android-x86_64.r2` / `android-x86.r2` | Android native |

**Vendor / embedded:**

| Profile | Target |
|---------|--------|
| `cisco-ios-mips32.r2` / `cisco-ios-ppc32.r2` | Cisco IOS |
| `cobham-sailor-arm.r2` / `cobham-e710-api.r2` / `cobham-e500-mips.r2` | Cobham SATCOM |
| `dji-flyc.r2` / `dji-gimbal.r2` / `dji-lightbridge.r2` / `dji-generic.r2` | DJI bare-metal |
| `dji-amba-sys.r2` / `dji-android-arm32.r2` / `dji-fly-android-arm64.r2` | DJI Android / Ambarella |
| `furuno-felcom-arm.r2` | Furuno FELCOM |
| `hpe-ilo7-arm64.r2` | HPE iLO 7 |
| `icom-vxworks-mips.r2` / `icom-ap90m-vxworks.r2` | Icom VxWorks |
| `intellian-arm-glibc.r2` | Intellian VSAT |
| `juniper-srx.r2` / `juniper-ppc32.r2` | Juniper SRX |
| `netgear-orbi-cgi.r2` | Netgear Orbi CGI |
| `spacex-starlink-musl-arm64.r2` | SpaceX Starlink |
| `supermicro-bmc-arm.r2` | Supermicro BMC |
| `vxworks7-x86_64.r2` | VxWorks 7 |
| `autel-aarch64.r2` | Autel drones |
| `bosch-cpp3.r2` / `bosch-cppenc.r2` | Bosch camera |
| `viasat-explorer-gx-arm.r2` | Viasat Explorer GX |

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
| `furuno/` | fursysmgr, libfurcommon |
| `icom/` | vxworks_kernel |
| `jrc/` | rmsd |
| `navico/` | rtspd |
| `dell/` | fcgi-auth, libdwebserver |
| `d-link/` | httpd |
| `paradigm/` | WebServer |

### Tools (`tool/`)

Content generators. All scripts are single-file Python or shell, self-documenting
(`--help`), and require only `r2pipe` beyond standard library.

**zsig generators:**

| Script | Produces |
|--------|---------|
| `generate-debian-libs-zsig.py` | `debian/{amd64,arm64,armhf,i386}/*.zsig` from Ubuntu 22.04 .deb packages |
| `generate-macos-zsig.py` | `macos/{arm64,x86_64}/*.zsig` — Apple open source + macOS SDK (no Apple hardware needed) |
| `generate-musl-zsig.py` | `musl/*/*.zsig` from musl libc source |
| `generate-openwrt-musl-zsig.py` | `openwrt/*/*.zsig` from OpenWrt toolchain tarballs |
| `generate-ndk-zsig.py` | `android/*/*.zsig` from Android NDK |
| `generate-uclibc-mipsbe-zsig.py` | `uclibc/mips{32,64,64-n32}/*.zsig` from Bootlin toolchain |
| `generate-uclibc-arm32-zsig.py` | `uclibc/arm32/*.zsig` from Bootlin armv5-eabi toolchain |
| `generate-uclibc-arm64-zsig.py` | `uclibc/arm64/*.zsig` from Bootlin aarch64 uclibc toolchain |
| `generate-freertos-zsig.py` | `embedded/arm-none-eabi/freertos-cm{0,3,4,7}.zsig` — compiled from FreeRTOS-Kernel source |
| `generate-go-zsig.py` | `go/{amd64,arm64,x86}/*.zsig` from Go stdlib |
| `generate-vcruntime-zsig.py` | `windows/*/vcruntime*.zsig` from VC++ runtime DLLs |
| `generate-winsdk-zsig.py` | `windows/*/` from Windows SDK static libs |
| `generate-vxworks-zsig.py` | `vxworks/*/*.zsig` from VxWorks SDK |
| `generate-juniper-zsig.py` | `juniper/*.zsig` from JunOS binaries |
| `generate-zsig.py` | Generic zsig generator from any static archive (.a) |
| `generate-all-windows-zsigs.sh` | Batch all VS versions × architectures |
| `generate-dji-symbols.py` | DJI `.r2` symbol scripts from .map files |

**Download helpers:**

| Script | Downloads |
|--------|----------|
| `download-android-ndk.py` | Android NDK for a specific version |
| `download-musl.py` | musl libc source |
| `download-openwrt-musl.py` | OpenWrt toolchain tarballs |
| `download-uclibc-mipsbe.py` | Bootlin uClibc MIPS toolchain |
| `download-vcredist.py` | VC++ redistributables (all versions) |
| `download-windows-sdk.py` | Windows SDK |
| `download-pdb.py` | PDB files from Microsoft symbol server |
| `fetch-windows-pdbs.sh` | Batch PDB download for DLLs in a directory |

**Corpus maintenance:**

| Script | Purpose |
|--------|---------|
| `prune-session-zsigs.py` | Remove `fcn.*` entries from session zsigs; merge duplicate-source pairs |
| `validate-corpus.py` | Validate zsig files, index.json, profile routing, orphan detection |
| `zsig_utils.py` | Shared utilities for zsig generation (not a standalone tool) |

### Documentation (`docs/`)

| File | Content |
|------|---------|
| `dji-firmware-formats.md` | DJI xV4, IM\*H, and Ambarella container structures |
| `dji-module-types.md` | DJI module type reference (target IDs, product codes) |
| `modality-firmware-workflows.md` | Modality (angr/Z3) symbolic execution workflows |
| `protocols/dji-dupc-0x55.md` | DJI DUPC 0x55 protocol specification |

---

## Common Workflows

### Container / Format Identification
```r2
r2 -n sample.bin
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
├── magic/           file/container format + crypto + protocol magic signatures
├── format/          pf print-format definitions (pf.uimage_header etc.)
├── types/           C headers: to <file> → aaft applies to imports
├── zigns/           function signatures: zo <file> → z/ to match
│   ├── tiers.json   tier taxonomy (core/vendor/debian-large/windows-large)
│   ├── sessions/    per-binary corpus (real local dir, receives new zsigs)
│   └── ...          core + vendor + large tiers (symlinked from skel/)
├── profiles/        analysis profiles: r2 -i <profile> binary
│   ├── profiles_config.json  auto-profile routing (arch/vendor/libc → profile)
│   └── libc/        libc sub-profiles (musl, glibc, bionic, uclibc)
├── symbols/         address-based .r2 scripts per vendor/binary
├── scripts/         r2 automation scripts sourced by profiles
│   ├── windows-sinks.r2          sink labeler for Windows PE
│   ├── windows-sinks-stripped.r2 comment-stripped version (for embedding)
│   ├── load-windows-sinks.r2     convenience wrapper
│   └── elf-sinks.r2              sink labeler for ELF binaries
├── tool/            zsig + symbol generation scripts
├── docs/            protocol docs, format specs, and workflow references
├── coverage.json    arch/vendor coverage matrix (profile+symbols+zsig status)
└── modality/        Modality (angr/Z3) symbolic execution bridge
```

---

## Philosophy

See [CONSTITUTION.md](CONSTITUTION.md) for principles. Open work items are in [TODO.md](TODO.md).
- **Enhance r2** — don't wrap or replace r2 commands
- **Unix philosophy** — small tools that compose well
- **Broad applicability** — reusable RE data; target-specific only when it adds value
- **Simplicity** — if r2 already does it, don't duplicate
