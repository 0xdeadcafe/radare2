# r2 Corpus Improvement Plan
> Assessment date: 2026-08-06
> Run `python3 tool/validate-corpus.py` after implementing each batch.
> Priority: **P0** silent-fail/wrong-analysis · **P1** quality · **P2** coverage · **P3** tooling · **P4** docs

---

## Current State Summary

**289 zsig files** covering:
- musl: 8 archs (aarch64, armhf, armv7, ppc64le, riscv64, s390x, x86, x86_64) ✅
- debian/amd64: 23 library zsigs ✅ | debian/arm64: 21 (missing 2 vs amd64) ⚠️
- glibc/armhf: 1 file (glibc-libc.zsig only, ~5351 sigs, no extras) ⚠️
- uclibc: arm32, mips32/64/64-n32 ✅
- openwrt: 5 MIPS variants ✅
- windows x64/x86: VS2008–VS2022 (comprehensive) ✅
- android NDK r27c: arm64-v8a, armeabi-v7a, x86, x86_64 ✅
- embedded arm-none-eabi: Newlib Cortex-M0/M3/M4/M7 ✅
- go 1.23: amd64, arm64, x86 ✅
- vxworks7: x86_64 ✅
- sessions: 11 corpus zsigs (all 100% named) ✅

**60+ profiles**, `validate-corpus.py` reports clean. WORKLIST P0-P3 items mostly
resolved. Key systemic issues remain in profile *defaults* and zsig *depth*.

---

## P0 — Auto-profile defaults (silent wrong analysis)

These affect every binary opened through `r2_open(auto_profile=True)` when the
correct vendor/libc isn't explicitly known.

### P0-1 `profiles_config.json`: `x86/32` defaults to `windows-x86.r2`

**Impact:** Every Linux i386 ELF binary (uClibc/glibc/musl x86_32 router firmware,
CTF binaries, older SATCOM daemons) gets Windows PE analysis settings:
`e asm.arch=x86; e asm.bits=32` is correct, but the Windows PE profile loads
VC++ vcruntime zsigs and Win32 type headers against a Linux ELF. The `to` commands
load `windows/functions.h` which incorrectly renames glibc imports to Win32 names.

**Fix:**
```json
// profiles_config.json — change:
"x86/32": "windows-x86.r2"
// to:
"x86/32": "linux-glibc-x86.r2"    ← create this profile (see P2-1)
```
The `libc_profiles` layer will then correctly override to musl-x86 when the
interpreter is `/lib/ld-musl-i386.so.1`.

For pure Windows PE targets, the PI `r2_open` auto-detect path reads `bin.os`
from rabin2 and should prefer PE-specific profiles. Wire `windows/x86` vendor
detection in `profiles_config.json` vendor_profiles rather than arch default.

### P0-2 `profiles_config.json`: no `arm/32` arch default

**Impact:** Every ARM32 ELF (the single most common embedded firmware arch:
OpenWrt devices, SATCOM terminals, NAS appliances, Supermicro BMC, etc.) that
isn't matched by a vendor-specific rule falls through `select_profile()` returning
`None`. `aether_r2profile.load_profile()` then skips all type loading and zsig
loading. The analyst opens a completely bare binary — no libc types, no signatures.

**Fix:**
```json
// profiles_config.json — add:
"arm/32": "linux-glibc-arm32.r2"
```
The `libc_profiles` layer (`arm/32/musl`, `arm/32/bionic`) will override correctly
when the interpreter is detected. `arm/32/uclibc` is currently **missing** from
`libc_profiles` — add it too:
```json
"arm/32/uclibc": "libc/uclibc-arm32.r2",
"arm/32/glibc":  "libc/glibc-arm32.r2"
```

### P0-3 `profiles_config.json`: no `arm/32/glibc` in `libc_profiles`

**Impact:** ARM32 glibc ELFs (Cobham, Furuno, Intellian, Navico, Raymarine,
generic Linaro-toolchain binaries) with `/lib/ld-linux-armhf.so.3` interpreter
are detected as `glibc` by `detect_libc()` but `select_libc_profile()` finds no
`arm/32/glibc` key → returns `None` → no glibc zsigs loaded. The `glibc-libc.zsig`
(5351 sigs) is silently skipped.

**Fix:** Add to `profiles_config.json` libc_profiles:
```json
"arm/32/glibc": "libc/glibc-arm32.r2"
```
`profiles/libc/glibc-arm32.r2` already exists — it just wasn't wired.

---

## P1 — Analysis Quality

### P1-1 Merge duplicate session zsig pairs (WORKLIST P1-5, still OPEN)

Two pairs of session zsigs exist from the same source binary:
- `0d97def03812819a` (178 sigs) + `403d19d7c890fd17` (134 sigs) → source `76bb8697`
- `6e9059417fa6324c` (35 sigs) + `daed52b867799857` (1319 sigs) → source `5716572f`

Loading both wastes time and risks double-rename false positives. Merge:

```bash
# For each pair, merge using rasign2, keep merged result, delete smaller:
r2 -q -c "zo zigns/sessions/6e9059417fa6324c.zsig; zo zigns/sessions/daed52b867799857.zsig; zos zigns/sessions/daed52b867799857.zsig" /dev/null
# Then delete the 35-sig stub and update index.json
```

**Tool:** `tool/prune-session-zsigs.py` — extend to support `--merge` flag using
`rasign2 -m merged.zsig a.zsig b.zsig` (requires rasign2 binary).

### P1-2 `glibc/armhf/glibc-libc.zsig` has unnamed `fcn.*` entries

The 5351-entry glibc ARM32 zsig contains entries named `fcn.0800XXXX` (Linaro
toolchain without full debug symbols). These pollute `z/` with phantom renames.

**Fix:**
```bash
python3 tool/prune-session-zsigs.py --keys glibc/armhf/glibc-libc.zsig
```
Or regenerate from a better source (Ubuntu armhf `libc6-dev` static `.a`).

### P1-3 `profiles_config.json` should map `bin.os = windows` to PE profiles

Currently `x86/32` fallback wrong (P0-1). Additionally the PE detection should
be based on `bin.os` field from rabin2, not just arch defaults. In
`aether_r2profile.select_profile()`, check `info.get("os","").lower() == "windows"`
before the arch lookup and route directly to the Windows profile family.

This prevents Linux i386 binaries from ever hitting `windows-x86.r2`.

### P1-4 `juniper-ppc32.r2` not wired to `profiles_config.json` (WORKLIST P1-7)

The profile exists but the `ppc/32` arch entry is missing from `arch_profiles`.
PPC32 Juniper `f5e1d8fb` family binaries fall through to no profile.

**Fix:**
```json
// profiles_config.json — add to arch_profiles:
"ppc/32": "juniper-ppc32.r2"
// add to vendor_profiles:
"ppc/32/juniper": "juniper-ppc32.r2"
```

---

## P2 — Coverage Expansion (new zsigs / profiles)

### P2-1 Create `linux-glibc-x86.r2` profile (Linux i386 32-bit glibc)

Required by P0-1 fix. Model after `linux-glibc-x64.r2`:

```r2
e asm.arch=x86
e asm.bits=32
e cfg.bigendian=false
e bin.plt.resolve=true
e anal.hasnext=true; e anal.jmp.tbl=true; e anal.strings=true; e bin.demangle=true
e zign.graph=true; e zign.refs=true; e zign.mincc=1; e zign.minsz=4
e dir.types=~/.local/share/radare2/types
to libc/functions.h; to libc/fcntl.h; to libc/errno.h; to libc/signal.h
zo debian/i386/libc6.zsig    ← generate this (see P2-2)
e asm.describe=true; e asm.cmt.col=60
```

Also add a `libc/glibc-x86.r2` sub-profile for use by other vendor profiles
targeting 32-bit x86 Linux.

### P2-2 Generate `debian/i386/` zsig set

Ubuntu 22.04 provides i386 packages via `archive.ubuntu.com`. The existing
`generate-debian-libs-zsig.py` already lists `"i386"` in `UBUNTU_POOLS` but
no i386 output exists.

**Action:**
```bash
cd /opt/aether/skel/.local/share/radare2/tool
python3 generate-debian-libs-zsig.py --arch i386
# Generates: debian/i386/libc6.zsig, libstdc++.zsig, libssl.zsig etc.
```

Expected output: ~15 zsig files covering i386 glibc, libssl, libcurl, zlib, etc.
This is the primary zsig set for older x86 Linux firmware (routers, NAS, SATCOM).

### P2-3 Generate `debian/arm64/libcrypto-static.zsig` + `libprotobuf.zsig`

arm64 is missing these 2 vs amd64. They are already defined in
`generate-debian-libs-zsig.py` for arm64 — just need to be run:

```bash
python3 generate-debian-libs-zsig.py --arch arm64
# Will regenerate all arm64 zsigs including the 2 missing ones
```

Update `profiles/linux-glibc-arm64.r2` and `libc/glibc-arm64.r2` to add:
```r2
zo debian/arm64/libcrypto-static.zsig
zo debian/arm64/libprotobuf.zsig
```

### P2-4 Generate `glibc/armhf/` extra library zsigs

Currently only `glibc-libc.zsig`. ARM32 glibc firmware frequently statically
links libssl, libcrypto, libcurl, zlib. Add:

```bash
python3 generate-debian-libs-zsig.py --arch armhf
# Generates debian/armhf/ set — then symlink/copy relevant ones to glibc/armhf/
```

Or update `libc/glibc-arm32.r2` to load from `debian/armhf/` directly
(consistent with how `libc/glibc-x64.r2` loads from `debian/amd64/`).

Update `linux-glibc-arm32.r2` and all vendor ARM32 profiles (cobham, furuno,
intellian, netgear-orbi-cgi, supermicro-bmc-arm) to load the expanded set.

### P2-5 Generate `debian/armhf/libc6.zsig` (Linaro vs Ubuntu)

The `glibc/armhf/glibc-libc.zsig` came from a Linaro toolchain. Replace it with
a clean Ubuntu 22.04 `armhf libc6-dev` build (better symbol quality, fewer
`fcn.*` entries):

```bash
python3 generate-zsig.py --deb libc6-dev_2.35-0ubuntu3.9_armhf.deb \
    -o debian/armhf/libc6.zsig
# Then update libc/glibc-arm32.r2 to: zo debian/armhf/libc6.zsig
```

### P2-6 macOS zsigs (x64 + arm64)

Both `macos-x64.r2` and `macos-arm64.r2` exist but load no zsigs.
Documented TODO in coverage.json.

**Sources:**
1. **Approach A (preferred):** Download Apple's open-source libc (libc-498.40.1)
   from `https://github.com/apple-oss-distributions/Libc` and compile with Xcode
   on Apple Silicon. Generate zsig from the resulting `.dylib`.
2. **Approach B (containers):** Extract libSystem.B.dylib from a macOS SDK
   tarball. r2's `rabin2 -s` can extract symbols without running the binary.
3. **Approach C (quick win):** Use Homebrew-installed binaries on Linux (via
   `osxcross`) — `libSystem.B.dylib` from the macOS SDK.

**Blockers:** Requires an Apple host or macOS SDK license. Mark as `OPEN`.
Add a `tool/download-macos-sdk.sh` placeholder that documents the manual steps.

### P2-7 FreeRTOS / Zephyr bare-metal zsigs

The `embedded/arm-none-eabi/` set covers Newlib libc for Cortex-M. Many IoT
devices use FreeRTOS or Zephyr RTOS with their own heap/task APIs.

**Action:**
1. Clone FreeRTOS-Kernel and build for Cortex-M3/M4 (`arm-none-eabi-gcc -O2`)
2. Run `generate-zsig.py --lib libfreertos.a -o embedded/freertos-cm3.zsig`
3. Add `zo embedded/freertos-cm3.zsig` to `dji-flyc.r2` and `dji-gimbal.r2`

**Value:** Immediately names `vTaskDelay`, `xQueueCreate`, `pvPortMalloc` in DJI
and IoT targets (these appear unnamed in almost every DJI flyc session).

### P2-8 uclibc-ng ARM64 zsigs

As embedded Linux moves to 64-bit (Raspberry Pi 4/5, Amlogic S905, Rockchip RK35xx),
uclibc-ng for ARM64 is increasingly common (OpenWrt AArch64 targets).

```bash
# Download Bootlin toolchain: aarch64--uclibc--stable-2024.02-1
python3 tool/download-uclibc-mipsbe.py   # adapt for AArch64 — new script needed
python3 tool/generate-uclibc-arm32-zsig.py  # adapt for arm64
# Output: uclibc/arm64/uclibc-libc.zsig
```

Create `tool/generate-uclibc-arm64-zsig.py` mirroring `generate-uclibc-arm32-zsig.py`.
Add `libc/uclibc-arm64.r2` sub-profile and wire to `profiles_config.json`.

### P2-9 OpenSSL static library zsigs (all archs)

Several embedded binaries statically link OpenSSL (libssl + libcrypto). The
`debian/amd64/libssl.zsig` and `debian/amd64/libcrypto-static.zsig` exist for
x64 only. ARM32 and ARM64 glibc targets commonly embed static OpenSSL.

**Action:**
- `debian/armhf/libssl.zsig` + `libcrypto-static.zsig` (via generate-debian-libs-zsig.py)
- `debian/arm64/libcrypto-static.zsig` (already P2-3)
- `musl/aarch64/libssl.zsig` — build OpenSSL against musl cross-compiler

---

## P3 — Tooling

### P3-1 `profiles_config.json`: add `bin.os` guard in `aether_r2profile.select_profile()`

`select_profile()` currently does pure arch+bits lookup with vendor overlay.
It should check `info.get("os","").lower()` first:
- `"windows"` → Windows PE profile family (regardless of `x86/32` arch default)
- `"ios"` → macOS/iOS profile family

```python
# In aether_r2profile.py select_profile():
os_hint = (info.get("os") or "").lower()
if os_hint in ("windows", "win32", "win64"):
    arch_key = f"{arch}/{bits}"
    # look up in a new windows_arch_profiles sub-map
    return _CONFIG.get("windows_profiles", {}).get(arch_key)
```

Add `windows_profiles` section to `profiles_config.json`:
```json
"windows_profiles": {
    "x86/32": "windows-x86.r2",
    "x86/64": "windows-x64.r2",
    "arm/64": "windows-arm64.r2"
}
```

### P3-2 `validate-corpus.py`: check `profiles_config.json` arch default sanity

Add `check_arch_defaults()` to the validator:
- Warn if `x86/32` routes to a PE profile (for Linux targets)
- Warn if `arm/32` has no default (major coverage gap)
- Warn if libc_profiles is missing `arm/32/glibc` or `arm/32/uclibc`
- Warn if any profile listed in profiles_config.json doesn't exist on disk

```python
def check_arch_defaults(r2dir: Path) -> list[str]:
    """Validate profiles_config.json routing logic."""
    ...
```

### P3-3 `tool/generate-debian-libs-zsig.py`: add `armhf` + `i386` to CI workflow

The tool already supports these architectures but they've never been run.
Add a `Makefile` target or `tool/build-all-zsigs.sh` that runs:

```bash
python3 generate-debian-libs-zsig.py --arch amd64
python3 generate-debian-libs-zsig.py --arch arm64
python3 generate-debian-libs-zsig.py --arch armhf
python3 generate-debian-libs-zsig.py --arch i386
```

Estimated runtime: ~30 minutes on first run (downloads .deb packages).

### P3-4 `tool/generate-uclibc-arm64-zsig.py` — new script

Clone `generate-uclibc-arm32-zsig.py`, change:
- Bootlin target: `aarch64--uclibc--stable-2024.02-1`
- Output dir: `zigns/uclibc/arm64/`
- Profile output: `profiles/libc/uclibc-arm64.r2`

### P3-5 `tool/download-pdb.py` — batch workflow for Windows targets

The script exists but is only used ad-hoc. Add a `tool/fetch-windows-pdbs.sh`
that downloads PDBs for the DLLs present in `zigns/windows/x64/`:
- `vcruntime140.dll`, `ucrtbase.dll`, `msvcp140.dll`, `concrt140.dll`
- Place in `~/.local/share/radare2/cache/pdb/`
- r2 auto-loads PDBs from `dir.dbg.bpdb` (set to this cache dir in `.radare2rc.local`)

This dramatically improves VC++ runtime analysis in Windows PE sessions.

### P3-6 Add `tool/prune-session-zsigs.py --merge` mode

Current tool only prunes unnamed entries. Add merge capability:
```bash
python3 tool/prune-session-zsigs.py --merge \
    0d97def03812819a 403d19d7c890fd17 \
    --output 0d97def03812819a
# Merges pair, keeps the hash of the larger one, updates index.json
```

---

## P4 — Documentation

### P4-1 Add `profiles/libc/glibc-arm32.r2` to the README table

Currently `libc/glibc-arm32.r2` is listed but the README doesn't clarify it
also loads `glibc/armhf/glibc-libc.zsig`. Update after P2-4 to reflect the
expanded zsig set.

### P4-2 Document `profiles_config.json` schema in `profiles/README.md`

The `arch_profiles` / `vendor_profiles` / `libc_profiles` keys are not documented
in the profiles README. Add a section explaining the routing logic and how to add
new entries without modifying Python code.

### P4-3 Update `coverage.json` after each fix

| Key | Current state | After plan |
|-----|---------------|------------|
| `arm-unknown` | profile=False | profile=True (P0-2 adds default) |
| `arm-netgear` | profile=False | profile=True (P0-2) |
| `arm-navico` | profile=False | profile=False (no dedicated profile yet) |
| `arm-raymarine` | profile=False | profile=False (no dedicated profile yet) |
| `x64-macos` | zsigs=False | zsigs=False (P2-6 blocked) |
| `aarch64-macos` | zsigs=False | zsigs=False (P2-6 blocked) |
| `aarch64-hpe` | zsigs=False | zsigs=False (binary not analysed) |

---

## Implementation Order

### Batch 1 — Immediate P0 fixes (< 1 hour, no downloads)
1. **P0-2**: Add `"arm/32": "linux-glibc-arm32.r2"` to `profiles_config.json` arch_profiles
2. **P0-3**: Add `"arm/32/glibc"` and `"arm/32/uclibc"` to `libc_profiles`
3. **P1-3**: Add `bin.os` Windows guard in `aether_r2profile.select_profile()`
4. **P1-4**: Add `ppc/32` and `ppc/32/juniper` to `profiles_config.json`
5. **P0-1**: Create `linux-glibc-x86.r2` (P2-1) first, then fix `x86/32` default

### Batch 2 — Zsig generation (30–60 min, requires network)
1. **P2-2**: `python3 tool/generate-debian-libs-zsig.py --arch i386`
2. **P2-3**: `python3 tool/generate-debian-libs-zsig.py --arch arm64` (adds missing 2)
3. **P2-4 + P2-5**: `python3 tool/generate-debian-libs-zsig.py --arch armhf`
4. Update `linux-glibc-arm32.r2` to load expanded `debian/armhf/` zsig set
5. Update `linux-glibc-x86.r2` to load `debian/i386/` zsig set

### Batch 3 — New zsig types (2–4 hours)
1. **P2-7**: FreeRTOS Cortex-M zsigs
2. **P2-8**: uclibc-ng ARM64 zsig + profile
3. **P1-1**: Session zsig pair merges

### Batch 4 — Tooling hardening (ongoing)
1. **P3-2**: `validate-corpus.py` arch default sanity checks
2. **P3-5**: PDB fetch workflow for Windows analysis
3. **P3-6**: `prune-session-zsigs.py --merge` mode

### Batch 5 — Blocked / external dependencies
1. **P2-6**: macOS zsigs (requires Apple host)
2. **P2-9**: OpenSSL musl ARM zsigs (requires musl cross-compiler setup)

---

## Quick Reference: What Each Binary Type Gets After These Fixes

| Binary type | Before fix | After fix |
|-------------|-----------|-----------|
| ARM32 glibc ELF (Cobham, Furuno, Navico, unknown) | No profile, no types, no zsigs | `linux-glibc-arm32.r2` + `glibc/armhf/` zsigs |
| ARM32 uclibc ELF (OpenWrt, Supermicro, Bosch) | No default → uclibc profiles only if vendor matched | `linux-glibc-arm32.r2` + `uclibc-arm32.r2` libc override |
| Linux i386 ELF (old router/NAS firmware) | `windows-x86.r2` 🔴 WRONG | `linux-glibc-x86.r2` + `debian/i386/` zsigs |
| x86_64 glibc ELF (CTF, server daemons) | `linux-musl-x64.r2` → corrected by libc override | Same path, but now `arm/32/glibc` fix unblocks ARM32 equivalents |
| PPC32 Juniper | No profile | `juniper-ppc32.r2` |
| DJI flyc / gimbal | RTOS but no FreeRTOS zsigs | + FreeRTOS Cortex-M zsigs (P2-7) |
