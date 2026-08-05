# Zignatures

Native r2 function signatures for identifying library functions in stripped binaries.
Loaded with `zo <file>`; manual matching is typically done with `z/` when your
workflow wants an explicit signature application pass.

## Quick Start

```r2
# Load a zignature file
zo ~/.local/share/radare2/zigns/musl/aarch64/musl-libc.zsig

# Search for matches in current binary
z/

# List matched functions
afl~zign.

# Combine zsig + FLIRT for best coverage
zo musl-libc.zsig
zfs musl-libc.sig
z/
```

## Directory Reference

### `android/` — Android NDK

| Path | Architecture | Description |
|------|-------------|-------------|
| `android/arm64-v8a/ndk-r27c.zsig` | AArch64 | Bionic libc + libm + libc++ (Android NDK r27c) |
| `android/armeabi-v7a/ndk-r27c.zsig` | ARM32 | 32-bit Android native |
| `android/x86_64/ndk-r27c.zsig` | x86-64 | Android emulator (64-bit) |
| `android/x86/ndk-r27c.zsig` | x86 | Android emulator (32-bit) |

**Use case:** Stripped Android native libs (`.so` extracted from APKs).

---

### `cisco-ios/` — Cisco IOS

| Path | Architecture | Description |
|------|-------------|-------------|
| `cisco-ios/mips32/ios-15.2.1T-c1900.zsig` | MIPS32 BE | IOS 15.2.1T C1900 function signatures |
| `cisco-ios/mips32/ios-15.0.1M-labels.r2` | MIPS32 BE | Address-based labels for IOS 15.0.1M |
| `cisco-ios/mips32/ios-15.1.3T1-labels.r2` | MIPS32 BE | Address-based labels for IOS 15.1.3T1 |
| `cisco-ios/mips32/ios-15.2.1T-labels.r2` | MIPS32 BE | Address-based labels for IOS 15.2.1T |
| `cisco-ios/mips32/ios-15.2.1T-structs.r2` | MIPS32 BE | Struct type script for IOS 15.2.1T |
| `cisco-ios/mips32/ios_core_labels.r2` | MIPS32 BE | Core IOS function labels (shared across versions) |
| `cisco-ios/ppc32/ios-12.3-pagent-c1700.zsig` | PPC32 BE | IOS 12.3 PAGENT for C1700 (PPC) |

Also contains: `ios_string_labeler.py`, `ios_struct_mapper.py` — helper scripts
for batch-labelling string references and struct layouts in IOS binaries.

---

### `debian/` — Debian Linux Libraries

Libraries from Debian with debug symbols (`-dev` packages). High match rate.

| Library | arm64 | amd64 | Description |
|---------|-------|-------|-------------|
| `libc6.zsig` | ✓ | ✓ | GNU C library (glibc) |
| `libgcc.zsig` | ✓ | ✓ | GCC runtime |
| `libssl.zsig` | ✓ | ✓ | OpenSSL libssl + libcrypto |
| `libmbedtls.zsig` | ✓ | ✓ | Mbed TLS |
| `libcurl.zsig` | ✓ | ✓ | cURL |
| `libevent.zsig` | ✓ | ✓ | libevent async I/O |
| `libgnutls.zsig` | ✓ | ✓ | GnuTLS |
| `liblzma.zsig` | ✓ | ✓ | XZ/LZMA compression |
| `libbz2.zsig` | ✓ | ✓ | bzip2 |
| `libbrotli.zsig` | ✓ | ✓ | Brotli compression |
| `zlib.zsig` | ✓ | ✓ | zlib compression |
| `libavformat.zsig` | ✓ | ✓ | FFmpeg container formats |
| `libavutil.zsig` | ✓ | ✓ | FFmpeg utilities |

---

### `dji/` — DJI Drone Firmware

| File | Description |
|------|-------------|
| `dji/DJIDevice.zsig` | DJI device SDK library functions |
| `dji/DJIUavService.zsig` | DJI UAV service Android library |
| `dji/libsdk_base-fly121.zsig` | DJI Fly app SDK base (version fly121) |
| `dji/libwaes-fly121.zsig` | DJI Fly app WAES (AES wrapper) library |

**Use case:** Identify DJI SDK functions in stripped DJI Android native libs.
Load via `profiles/dji-fly-android-arm64.r2` or `profiles/dji-android-arm32.r2`.

---

### `embedded/` — Bare-Metal / RTOS

#### `embedded/arm-none-eabi/` — Newlib for Cortex-M

| File | CPU Target | Description |
|------|-----------|-------------|
| `newlib-v6m.zsig` | Cortex-M0/M0+ | ARMv6-M Thumb (no FPU) |
| `newlib-v7m.zsig` | Cortex-M3 | ARMv7-M Thumb-2 (no FPU) |
| `newlib-v7em.zsig` | Cortex-M4/M7 | ARMv7E-M Thumb-2 + FPU |
| `newlib-libm-v7em.zsig` | Cortex-M4/M7 | libm (math) for ARMv7E-M FPU |

**Use case:** Identify newlib C library functions in DJI FlyC (STM32F4),
gimbal (STM32F103), or other Cortex-M firmware.

---

### `glibc/` — GNU C Library (Targeted Builds)

Architecture-specific glibc builds matching real hardware toolchains
(more accurate than Debian `libc6.zsig` for non-standard toolchains).

| Path | Description |
|------|-------------|
| `glibc/armhf/glibc-libc.zsig` | glibc ARM hard-float (Cortex-A, Linaro toolchain) |

**Note:** This corpus currently carries a targeted glibc zsig only for ARMHF.
For x86-64 and arm64 glibc, use `debian/amd64/libc6.zsig` or
`debian/arm64/libc6.zsig` — those are also glibc and have broader coverage.

---

### `juniper/` — Juniper JunOS

| File | Description |
|------|-------------|
| `juniper/junos-kmd-21.3.zsig` | JunOS `kmd` (key management daemon) — JunOS 21.3R1.9 |
| `juniper/junos-kmd-21.3-sigdb.json` | Signature database metadata for kmd zsig |

**Use case:** Identify kmd functions in Juniper SRX firmware. Load via
`profiles/juniper-srx.r2`.

---

### `musl/` — musl libc (Alpine / Generic Builds)

Generic musl builds per architecture. Use `openwrt/` for router firmware
(ISA-specific CFLAGS produce better matches for router targets).

| Path | Description |
|------|-------------|
| `musl/aarch64/musl-libc.zsig` | musl AArch64 |
| `musl/armhf/musl-libc.zsig` | musl ARM32 hard-float (Cortex-A) |
| `musl/armv7/musl-libc.zsig` | musl ARM32 ARMv7 variant |
| `musl/x86/musl-libc.zsig` | musl x86 32-bit |
| `musl/x86_64/musl-libc.zsig` | musl x86-64 |
| `musl/ppc64le/musl-libc.zsig` | musl PPC64LE |
| `musl/riscv64/musl-libc.zsig` | musl RISC-V 64 |
| `musl/s390x/musl-libc.zsig` | musl s390x |

---

### `openwrt/` — musl libc (OpenWrt Target-Specific Builds)

Built with exact ISA/ABI CFLAGS matching each OpenWrt target.
**More accurate than generic musl for router firmware.**
Source: OpenWrt 24.10.6 toolchain tarballs.

| Path | CPU Profile | Real Hardware |
|------|------------|---------------|
| `openwrt/mips_24kc/musl-libc.zsig` | MIPS 24Kc | TP-Link WR841N/WR1043ND, Atheros AR9xxx |
| `openwrt/mipsel_24kc/musl-libc.zsig` | MIPSel 24Kc | Xiaomi MiWiFi 3, ASUS RT-N56U, MT7621 |
| `openwrt/mipsel_mips32/musl-libc.zsig` | MIPSel MIPS32r1 | Linksys WRT54G, Netgear WGR614, BCM47xx |
| `openwrt/mips_mips32/musl-libc.zsig` | MIPS MIPS32r1 | Livebox 2, HomeHub 2B, BT HH3, BCM63xx |
| `openwrt/mips64_octeonplus/musl-libc.zsig` | MIPS64 OcteonPlus | Ubiquiti EdgeRouter Lite/4, Cavium Octeon |

Each file has ~15,600 signatures.

---

### `uclibc/` — uClibc-ng (Legacy Embedded Linux)

Bootlin cross-toolchain builds. Found in older routers, DSL gateways,
IP cameras (pre-musl era). Source: toolchains.bootlin.com

| Path | ABI | Real Hardware |
|------|-----|---------------|
| `uclibc/mips32/uclibc-libc.zsig` | MIPS32r1, soft-float, BE | AR7 gateways, BCM5350, old OpenWrt/DD-WRT |
| `uclibc/mips64/uclibc-libc.zsig` | MIPS64, N64 ABI, soft-float, BE | Cavium Octeon, SiByte MIPS64 |
| `uclibc/mips64-n32/uclibc-libc.zsig` | MIPS64, N32 ABI, soft-float, BE | Octeon III, BCM1xxx |

---

### `vxworks/` — VxWorks 7 Libraries

| Path | Description |
|------|-------------|
| `vxworks/x86_64/vxworks7-libc.zsig` | VxWorks 7 libc (x86-64 Intel BSP) |
| `vxworks/x86_64/vxworks7-libssl.zsig` | OpenSSL for VxWorks 7 |
| `vxworks/x86_64/vxworks7-libcrypto.zsig` | libcrypto for VxWorks 7 |
| `vxworks/x86_64/vxworks7-libcurl.zsig` | libcurl for VxWorks 7 |
| `vxworks/x86_64/vxworks7-libz.zsig` | zlib for VxWorks 7 |
| `vxworks/x86_64/vxworks7-libmbedtls_hash.zsig` | Mbed TLS hash routines |
| `vxworks/x86_64/vxworks7-libxml.zsig` | libxml2 for VxWorks 7 |
| `vxworks/x86_64/vxworks7-sqlite3.zsig` | SQLite3 for VxWorks 7 |
| `vxworks/x86_64/vxworks7-libmosquitto.zsig` | MQTT Mosquitto for VxWorks 7 |
| `vxworks/x86_64/vxworks7-libbz2.zsig` | bzip2 for VxWorks 7 |
| `vxworks/x86_64/vxworks7-libcjson.zsig` | cJSON for VxWorks 7 |

Load via `profiles/vxworks7-x86_64.r2`.

---

### `windows/` — Windows VC++ Runtime

VS2008 through VS2022, both x86 and x64 and arm64. Covers:
- `vcruntime140` — core CRT (memcpy, malloc, exception handling)
- `ucrtbase` — Universal CRT (printf, fopen, etc.)
- `msvcp140` — C++ STL (std::string, std::vector, streams)
- `concrt140`, `vcamp140`, `vcomp140` — Parallel Patterns / OpenMP
- `mfc140`, `atl` — MFC and ATL frameworks

**Known gaps:**
- `vs2019-mfc140.zsig` absent for x64 (use `vs2017-mfc140.zsig` instead)
- `ucrtbase.zsig` absent for vs2019/vs2022 x86 (use `vs2017-ucrtbase.zsig`)

---

### `sessions/` — Per-Binary Session Corpus

Zsig files generated from specific analyzed binaries. Named by binary hash.
The `index.json` manifest maps hashes to metadata.

```json
{
  "acac7f0a3e4468c8": {
    "arch": "arm/32",
    "binary": "ipmi.cgi",
    "platform": "Supermicro_BMC",
    "status": "POC_FOUND",
    "function_count": 219,
    "named_pct": 97
  }
}
```

These are high-value signatures: 95–100% named functions from confirmed
POC-level analyses. Load when analysing the same binary version:

Note: AETHER's profile loader can load session zsigs automatically; if you are
working interactively in raw r2, load them manually as shown below.

```r2
zo ~/.local/share/radare2/zigns/sessions/acac7f0a3e4468c8.zsig
z/
```

Or query the index to find the right file:
```bash
python3 -c "
import json; d=json.load(open('~/.local/share/radare2/zigns/sessions/index.json'))
for h,m in d.items():
    print(h[:16], m.get('source_binary','?'), m.get('entry_count',0), m.get('named_pct','?'))
"
```

## zsig vs FLIRT Comparison

Both formats are complementary — they match different functions:

| Library | zsig | FLIRT | Combined |
|---------|------|-------|----------|
| libc6 (glibc) | ~82 | ~38 | ~108 |
| zlib | ~61 | ~4 | ~61 |
| musl libc | ~320 | ~180 | ~430 |

**Recommendation:** Use both for maximum coverage:
```r2
zo libc6.zsig
zfs libc6.sig
z/
```

## Generating New Zignatures

```bash
# Linux library (from -dev .deb package)
./tool/generate-zsig.py --deb libssl-dev_3.0.0_amd64.deb -o libssl.zsig

# musl libc (all architectures)
./tool/generate-musl-zsig.py --all

# Android NDK
./tool/generate-ndk-zsig.py --all

# Windows VC++ runtime
./tool/download-vcredist.py --all
./tool/generate-vcruntime-zsig.py --version 2022 --arch x64

# OpenWrt musl (per target)
./tool/generate-openwrt-musl-zsig.py --target mips_24kc

# VxWorks libraries
./tool/generate-vxworks-zsig.py --arch x86_64

# Juniper kmd
./tool/generate-juniper-zsig.py
```
