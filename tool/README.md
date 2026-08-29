# r2-config Tools

Scripts for generating and maintaining radare2 corpus content (zignatures, symbols,
type headers). All tools are single-file Python or shell scripts, self-documenting
(`--help`), and require only `r2pipe` beyond the standard library.

## Environment

All tools use `R2_DATA_DIR` (default: `~/.local/share/radare2`):
- Downloads cached in `$R2_DATA_DIR/cache/`
- Zsigs written to `$R2_DATA_DIR/zigns/`

Override:
```bash
R2_DATA_DIR=/opt/aether/skel/.local/share/radare2 python3 tool/generate-debian-libs-zsig.py --arch armhf
```

## Dependencies

- Python 3.8+, r2pipe (`pip install r2pipe`), radare2, `llvm-nm`
- `ar`, `nm` — binutils (static archive extraction)
- `llvm-ar` — Windows SDK `.lib` extraction (`apt install llvm`)
- `zstd` — OpenWrt toolchain streaming (`apt install zstd`)
- `cabextract` or `7z` — VC++ redistributable extraction
- `clang` — compilation targets for FreeRTOS, macOS, uclibc zsig generation

---

## zsig Generators

### `generate-debian-libs-zsig.py`

Generate zsigs from Ubuntu 22.04 (jammy) `-dev` packages. Downloads `.deb` files,
extracts static `.a` archives, and generates zsigs. Produces `debian/{arch}/*.zsig`.

```bash
python3 tool/generate-debian-libs-zsig.py --arch armhf
python3 tool/generate-debian-libs-zsig.py --arch i386
python3 tool/generate-debian-libs-zsig.py --arch arm64   # adds missing files
python3 tool/generate-debian-libs-zsig.py --all-arches   # all four arches
python3 tool/generate-debian-libs-zsig.py --list         # show available targets
```

### `generate-macos-zsig.py`

Generate native macOS libSystem and libm zsigs. Downloads the macOS SDK from
`joseluisq/macosx-sdks` (no Apple hardware needed), downloads Apple open source
(`apple-oss-distributions/Libc` + `Libm`), cross-compiles with
`clang --target=<arch>-apple-macos` using the SDK as sysroot, and generates zsigs.

```bash
python3 tool/generate-macos-zsig.py                  # all arches (arm64 + x86_64)
python3 tool/generate-macos-zsig.py --arch arm64
python3 tool/generate-macos-zsig.py --sdk-version 15.4
python3 tool/generate-macos-zsig.py --force          # regenerate existing
python3 tool/generate-macos-zsig.py --list           # show targets
```

### `generate-musl-zsig.py`

Generate zsigs from musl libc source. Downloads musl, compiles for each arch.

```bash
python3 tool/generate-musl-zsig.py --all
python3 tool/generate-musl-zsig.py --arch aarch64
```

### `generate-openwrt-musl-zsig.py`

Generate zsigs from OpenWrt toolchain tarballs (ISA-specific CFLAGS).

```bash
python3 tool/generate-openwrt-musl-zsig.py --target mips_24kc
python3 tool/generate-openwrt-musl-zsig.py --all
```

### `generate-ndk-zsig.py`

Generate zsigs from Android NDK Bionic libc.

```bash
python3 tool/generate-ndk-zsig.py --all
python3 tool/generate-ndk-zsig.py --abi arm64-v8a
```

### `generate-freertos-zsig.py`

Generate zsigs from FreeRTOS-Kernel source. Downloads from GitHub, compiles
Cortex-M port files with `clang --target=arm-none-eabi`.

```bash
python3 tool/generate-freertos-zsig.py                     # all CM variants
python3 tool/generate-freertos-zsig.py --targets cm3 cm4
python3 tool/generate-freertos-zsig.py --version V11.1.0
```

### `generate-uclibc-mipsbe-zsig.py`

Generate zsigs from uClibc-ng Bootlin toolchain for MIPS (mips32, mips64, mips64-n32).

```bash
python3 tool/generate-uclibc-mipsbe-zsig.py
```

### `generate-uclibc-arm32-zsig.py`

Generate zsigs from uClibc-ng Bootlin toolchain for ARM32 (armv5-eabi).

```bash
python3 tool/generate-uclibc-arm32-zsig.py
```

### `generate-uclibc-arm64-zsig.py`

Generate zsigs from uClibc-ng Bootlin toolchain for AArch64.

```bash
python3 tool/generate-uclibc-arm64-zsig.py
```

### `generate-go-zsig.py`

Generate zsigs from the Go standard library.

```bash
python3 tool/generate-go-zsig.py --all
python3 tool/generate-go-zsig.py --arch amd64
```

### `generate-vcruntime-zsig.py`

Generate zsigs from VC++ runtime DLLs. Requires downloaded redistributables
(use `download-vcredist.py` first).

```bash
python3 tool/download-vcredist.py --all
python3 tool/generate-vcruntime-zsig.py --version 2022 --arch x64
python3 tool/generate-all-windows-zsigs.sh    # batch all VS × arch combinations
```

### `generate-winsdk-zsig.py`

Generate zsigs from Windows SDK static libraries. Requires a local Windows SDK
installation (not freely downloadable; use `download-windows-sdk.py` first or
supply a pre-installed path).

```bash
python3 tool/generate-winsdk-zsig.py --arch x64
```

### `generate-vxworks-zsig.py`

Generate zsigs from VxWorks SDK libraries.

```bash
python3 tool/generate-vxworks-zsig.py --arch x86_64
```

### `generate-juniper-zsig.py`

Generate zsigs from JunOS binaries (requires access to JunOS firmware).

```bash
python3 tool/generate-juniper-zsig.py
```

### `generate-zsig.py`

Generic zsig generator. Works on any static archive (`.a`) or ELF binary.

```bash
python3 tool/generate-zsig.py --lib path/to/libc.a -o libc.zsig
python3 tool/generate-zsig.py --deb libssl-dev_3.0.0_amd64.deb -o libssl.zsig
```

### `generate-dji-symbols.py`

Generate r2 symbol scripts (`.r2`) from DJI `.map` files for address-based labelling.

```bash
python3 tool/generate-dji-symbols.py --map flyc_v01.09.0850.map -o symbols/dji/flyc/
```

---

## Download Helpers

### `download-android-ndk.py`

Download the Android NDK for a specific version.

### `download-musl.py`

Download musl libc source.

### `download-openwrt-musl.py`

Download OpenWrt toolchain tarballs (multiple ISA targets).

### `download-uclibc-mipsbe.py`

Download Bootlin uClibc-ng MIPS toolchain tarballs.

### `download-vcredist.py`

Download VC++ redistributable packages (all VS versions, all arches).

### `download-windows-sdk.py`

Download the Windows SDK (requires a Windows installation or SDK offline installer).

### `download-pdb.py`

Download PDB files from the Microsoft symbol server for a given DLL/EXE.

```bash
python3 tool/download-pdb.py --binary vcruntime140.dll --output ~/.local/share/radare2/cache/pdb/
```

### `fetch-windows-pdbs.sh`

Batch wrapper around `download-pdb.py`. Downloads PDBs for all DLLs in a directory.

```bash
bash tool/fetch-windows-pdbs.sh target.dll
bash tool/fetch-windows-pdbs.sh /mnt/windows/System32/   # batch
```

---

## Corpus Maintenance

### `prune-session-zsigs.py`

Remove `fcn.*`/`sub.*` entries from low-quality session zsigs; merge
duplicate-source session pairs.

```bash
# Dry-run: show what would change
python3 tool/prune-session-zsigs.py --r2dir . --dry-run

# Prune sessions below 80% named
python3 tool/prune-session-zsigs.py --r2dir . --threshold 80

# Merge two duplicate-source sessions
python3 tool/prune-session-zsigs.py --merge BASE_HASH:ABSORB_HASH
```

### `validate-corpus.py`

Validate the full corpus: zsig files, `index.json` consistency, profile routing
sanity, dead type headers, orphaned zsigs.

```bash
# Run from corpus root
cd /opt/aether/skel/.local/share/radare2
python3 tool/validate-corpus.py

# Machine-readable output
python3 tool/validate-corpus.py --json
```

### `zsig_utils.py`

Shared library used by all generation scripts. Not a standalone tool.

Provides:
- `generate_zsig_from_lib()` — generate zsig from a static `.a` archive
- `generate_zsig_batch()` — batched processing for large object sets
- `merge_zsigs()` — merge multiple zsig files into one
- `extract_objects_from_archive()` — extract `.o` files from `.a`
- `open_r2()` — context manager for r2pipe sessions
