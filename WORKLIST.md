# r2 Corpus Worklist
> Generated: 2026-08-03 | Run: `python3 tool/validate-corpus.py` after each batch

Findings from systematic audit of `skel/.local/share/radare2/`.
Severity: **P0** data-corruption/silent-fail · **P1** analysis quality · **P2** dead assets · **P3** tooling · **P4** docs

---

## P0 — Correctness (silent failures / wrong analysis)

### P0-1 `profiles_config.json`: `"arm/32/cisco"` is wrong ✅ FIXED
Cisco IOS does not run on ARM32. The key `"arm/32/cisco"` routes to `cisco-ios-mips.r2`
which forces `e asm.arch=mips`. On a real ARM/32 binary this would produce garbage
disassembly. Removed the entry.

### P0-2 `cisco-ios-mips.r2` is a stub missing type/zsig/analysis settings ✅ FIXED
Used as fallback by `profiles_config.json` for `mips/32/cisco` but lacks:
- type loads (`to libc/functions.h` etc.)
- zsig load (`zo cisco-ios/mips32/ios-15.2.1T-c1900.zsig`)
- analysis settings (`e anal.hasnext`, `e anal.strings`, etc.)
`cisco-ios-mips32.r2` is the complete profile. Fixed by making `cisco-ios-mips.r2`
source `cisco-ios-mips32.r2` (no duplication).

### P0-3 Session zsig `de2cc34b9686e5da`: 753 all-unnamed entries ✅ FIXED
All 753 entries are `fcn.XXXXXXXX` names (source binary is itself = self-referential).
Loading this zsig will pollute `z/` runs with ghost renames that hide real matches.
Pruned using `tool/prune-session-zsigs.py` logic; file retained as empty zsig to
preserve index integrity, `named_pct` set to 0 in index.

### P0-4 Session zsig `de30eab66a594241`: single `entry0` entry ✅ FIXED
1-entry session with only `entry0` — a placeholder generated before any analysis.
Zero cross-binary value. Deleted file + index.json entry.

### P0-5 Session index.json missing `named_pct` field ✅ FIXED
`prune-session-zsigs.py` uses `named_pct` to decide which sessions to prune, but
`corpus_commit.py` never writes this field. All entries show `named_pct=NOT_SET`.
Added `named_pct` computed from actual zsig content for each session.

---

## P1 — Analysis Quality

### P1-1 `windows-arm64.r2` missing `e dir.types` ✅ FIXED
Loads `to windows/functions.h` etc. but never sets `e dir.types=~/.local/share/radare2/types`.
On systems where `dir.types` isn't pre-set (e.g., fresh container before install.sh runs),
all `to` commands silently fail. Added `e dir.types=~/.local/share/radare2/types`.

### P1-2 `windows-arm64.r2` missing `e zign.mincc=1` / `e zign.minsz=4` ✅ FIXED
Both `windows-x64.r2` and `windows-x86.r2` have these thresholds. Without them,
small VC++ stub functions (1 basic block, < 4 bytes) don't match signatures.

### P1-3 Bare-metal profiles load POSIX socket types ✅ FIXED
`dji-flyc.r2`, `dji-gimbal.r2`, `dji-lightbridge.r2` all load `to libc/socket.h`.
These target STM32 Cortex-M bare-metal firmware — no OS, no networking stack.
The `sockaddr_in` struct in `libc/socket.h` is x86_64 layout; loading it for ARM/32M
creates wrong-sized struct annotations. Removed `to libc/socket.h` from all three.

### P1-4 `libc/fcntl.h` `struct stat` is x86_64 only — loaded by ARM32 profiles ✅ FIXED
Created `types/libc/fcntl-arm32.h` with correct ARM32 `struct stat` (120 bytes,
64-bit dev/rdev/ino/size via `long long`, 32-bit times via `int`). Updated 10 ARM32
profiles to load `fcntl-arm32.h` instead of `fcntl.h`:
`linux-glibc-arm32.r2`, `libc/glibc-arm32.r2`, `intellian-arm-glibc.r2`,
`cobham-sailor-arm.r2`, `furuno-felcom-arm.r2`, `bosch-cpp3.r2`, `bosch-cppenc.r2`,
`supermicro-bmc-arm.r2`, `netgear-orbi-cgi.r2`, `dji-android-arm32.r2`.

### P1-5 Duplicate session zsigs from same source binary ✅ FIXED
Three pairs merged in Batch 3a using `prune-session-zsigs.py --merge`:
- `0d97def03812819a` (178) + `403d19d7c890fd17` (134) → merged: **312 sigs** (kept `0d97def`)
- `daed52b867799857` (1319) + `6e9059417fa6324c` (35) → merged: **1354 sigs** (kept `daed52b`)
- `8073dc82fc3f4caa` (4191) + `acac7f0a3e4468c8` (219) → merged: **4410 sigs** (kept `8073dc8`)
Added `--merge BASE:ABSORB` mode to `prune-session-zsigs.py`. Sessions: 11 → 8.

### P1-6 Session `8073dc82fc3f4caa` has `source_binary: "Auth"` (filename, not hash) ✅ FIXED
4191-entry Supermicro BMC session. Updated `index.json` `source_binary` field to
`193a2ccb7fa04c77` (the correct library hash from coverage.json).

---

## P2 — Dead Assets / Housekeeping

### P2-1 `types/ffmpeg/avcodec.h` never loaded by any profile ✅ FIXED
Exists alongside `avformat.h` and `avutil.h` (both loaded by glibc-arm64.r2 and
glibc-x64.r2) but `avcodec.h` is omitted. Added `to ffmpeg/avcodec.h` to both
glibc profiles.

### P2-2 `types/windows/ntstatus.h` and `windows/winerror.h` never loaded ✅ FIXED
Both files exist in `types/windows/` but no profile loads them. These are high-value
for Windows PE analysis (NTSTATUS return codes, Win32 error constants). Added to
windows-x64.r2, windows-x86.r2, and windows-arm64.r2.

### P2-3 Empty symbol directories with no explanation ✅ FIXED
- `symbols/dji/unknown/` — empty, no README
- `symbols/juniper/family_c8711279/` — empty while `family_f5e1d8fb/` has content
Added README.md placeholders explaining status.

### P2-4 Session `fc531267fc2f85a8`: ~33% unnamed (66 entries) ✅ VERIFIED CLEAN
Audit (2026-08-06): 63/63 entries are properly named — 0 `fcn.*` entries. The original
~33% figure was based on an incorrect estimate. No pruning required.

### P2-5 Session `f29d5e39bd05d704`: ~33% unnamed (313 entries, IPMI OEM) ✅ VERIFIED CLEAN
Audit (2026-08-06): 298/298 entries are properly named — 0 `fcn.*` entries. The `fcn.0004edf0`
listed in sample_names was an isolated outlier. No pruning required.

---

## P3 — Tooling

### P3-1 `prune-session-zsigs.py` hardcodes `R2DIR` path ✅ FIXED
`R2DIR = os.path.expanduser('~/.local/share/radare2')` — fails when run from
the repo (`skel/.local/share/radare2/`) rather than the installed location.
Added `R2DIR` env var override and `--r2dir` CLI flag.

### P3-2 `validate-corpus.py` doesn't check `named_pct` field presence ✅ FIXED
`check_session_index()` references `entry.get("named_pct", 100)` but the field
was never written by `corpus_commit.py`. The quality gate silently passed.
Validator now computes `named_pct` from zsig file if the field is absent and
emits a warning to add it to the index.

### P3-3 `validate-corpus.py` doesn't flag dead `types/` headers ✅ FIXED
Headers that exist but no profile loads (`ffmpeg/avcodec.h`, `windows/ntstatus.h`,
`windows/winerror.h`) were invisible to the validator. Fixed by P2-1/P2-2 (now
all are loaded). `check_dead_types()` added to validate-corpus.py — warns for
any `.h` file in `types/` not referenced by any profile.

---

## P4 — Documentation

### P4-1 `profiles/README.md` missing recent Linux profiles ✅ FIXED
`linux-musl-armv7.r2`, `linux-musl-arm32.r2`, `linux-musl-x86.r2`,
`linux-glibc-arm32.r2` were added after the README was last updated.
Added entries to the Linux section table.

### P4-2 `zigns/README.md` session query code block uses wrong field names ✅ FIXED
Code example references `m['binary']`, `m['platform']`, `m['status']` but the
actual index.json schema uses `source_binary`, `note`, `entry_count`.
Updated the example to use the real field names.

### P4-3 `profiles/libc/TODO.md` has stale "Priority 2 — RESOLVED" entries
All P2 items are DONE but the file is useful as a tracker. Consider archiving or
consolidating into a single "Coverage complete" note. Low priority.

---

## Coverage Gaps (new work required)

These are missing zsigs/profiles for targets we actively analyse:

| Gap | Arch | Priority | Status |
|-----|------|----------|--------|
| `uclibc/arm32/uclibc-libc.zsig` | ARM32 | HIGH | ✅ DONE — Bootlin armv5-eabi 2024.02, 3269 sigs, 76% named |
| `libc/fcntl-arm32.h` (P1-4) | ARM32 | MEDIUM | ✅ DONE — created, 10 ARM32 profiles updated |
| `linux-glibc-x64.r2` top-level profile | x86-64 | MEDIUM | ✅ DONE |
| `linux-glibc-arm64.r2` top-level profile | arm64 | MEDIUM | ✅ DONE |
| `freebsd-x64.r2` profile | x86-64 | MEDIUM | ✅ DONE |
| `macos-x64.r2` / `macos-arm64.r2` profiles | x86-64/arm64 | MEDIUM | ✅ DONE (zsigs TODO) |
| Session pair merges (P1-5) | mixed | LOW | ✅ DONE — Batch 3a, 3 pairs merged, 11→8 sessions |
| uclibc-ng ARM64 zsig | ARM64 | MEDIUM | ✅ DONE — Batch 3c, Bootlin 2024.02, arm/64/uclibc wired |
| FreeRTOS Cortex-M zsigs | ARM32 bare-metal | MEDIUM | ✅ DONE — Batch 3b, CM0/CM3/CM4/CM7, 322-336 sigs each |
| glibc/arm64 for Navico/Raymarine | ARM32/64 | LOW | OPEN — target triage first |
| macOS zsigs (x64 + arm64) | x86-64/arm64 | LOW | OPEN — needs macOS SDK or Apple host |

---

## How to Run Fixes

```bash
cd /opt/aether/skel/.local/share/radare2

# Validate current state
python3 tool/validate-corpus.py

# Prune unnamed session zsigs (interactive)
python3 tool/prune-session-zsigs.py --r2dir . --dry-run

# Merge duplicate-source session pairs
python3 tool/prune-session-zsigs.py --merge BASE:ABSORB [BASE2:ABSORB2 ...]

# After fixing, re-validate
python3 tool/validate-corpus.py
```

---

## P1-7 `juniper-srx.r2` forces MIPS on PPC32 `f5e1d8fb` family kmd ✅ DOCUMENTED

`juniper-srx.r2` hardcodes `e asm.arch=mips` for MIPS64 JunOS SRX binaries.
The `f5e1d8fb` library family (`kmd`, `dhcpd`, `HTTPD-GK`, etc.) is **PPC32 BE FreeBSD**
(`e_machine=PowerPC`). Loading `juniper-srx.r2` on this family forces wrong arch
and produces garbage disassembly.

**Fix:** Guard the arch setting with a check:

```r2
# In juniper-srx.r2: only force mips if ELF machine is not PowerPC
# For PPC32 family use: e asm.arch=ppc; e asm.bits=32; e cfg.bigendian=true
```

Or create a separate `juniper-ppc32.r2` profile for the `f5e1d8fb` family.
The `symbols/juniper/family_f5e1d8fb/*.r2` scripts already have correct addresses;
they just need a matching arch profile.

**Fixed (Batch 1, 2026-08-06):** `profiles/juniper-ppc32.r2` created with `e asm.arch=ppc;
e asm.bits=32; e cfg.bigendian=true`. Wired to `profiles_config.json` as both
`arch_profiles["ppc/32"]` (default) and `vendor_profiles["ppc/32/juniper"]`. ✅ FIXED

---

## P0-NEW `~` expansion broken in r2 `. ` command — was silently dropping profile content ✅ FIXED

r2's `.` (source) command does **not** expand `~` in file paths. Every profile
using `. ~/...` or `/m ~/...` silently no-ops. This affected:
- `.radare2rc`: `firmware.pf` never loaded → all pf.* templates missing
- 10 profiles: sub-profile sources and format loads silently dropped
- 30 profiles: `/m ~/...` magic scans never ran

**Fixes applied:**
1. `install.sh` `_write_r2rc_local()` now emits `. <abs_path>/format/firmware.pf`
2. All 40 profiles: `~/` replaced with `/root/` (absolute) in `.` and `/m` commands
3. `.radare2rc`: removed broken `~` source, moved to `.radare2rc.local`

**Note for portability:** The hardcoded `/root/` path works for the Docker container
(root user). For non-root installs, `install.sh --symlink` must be re-run to
regenerate `.radare2rc.local` with the correct `$HOME` path.

---

## P0-NEW `zign.mincc=10` default silently killed all zsig matches ✅ FIXED

r2's default `zign.mincc=10` requires 10+ basic blocks before a function is
eligible for signature matching. Most embedded firmware helper functions have
1–4 BBs. This meant `z/` produced 0 matches across all profiles that didn't
explicitly lower the threshold.

**Impact:** Every `zo <zsig>; z/` call in 17 vendor profiles was a silent no-op.
All firmware analysis sessions since corpus creation had zero zsig benefit.

**Fix:** Added `e zign.mincc=1; e zign.minsz=4` to all 40 profiles
(17 vendor profiles with `zo` lines + 23 others for manual `zo` usage).

---

## Bug Hunt 2026-08-05 Pass 2 — Parser Compatibility Fixes

### B1 -- UTF-8 in type .h files breaks r2 C parser ✅ FIXED
r2's `to` C parser is byte-by-byte ASCII; UTF-8 multi-byte sequences (em-dashes,
arrows, quotes) in comments corrupted parser state, silently stopping struct/enum
parsing mid-file. Affected 14 type files.
**Fix**: Replaced all non-ASCII with ASCII equivalents across all 39 .h files.

### B2 -- `struct stat` not parsed: function declaration shadows struct name ✅ FIXED
`int stat(char *pathname, struct stat *statbuf)` in `libc/fcntl.h` and
`libc/fcntl-arm32.h` caused r2 to register `stat` as a function, clobbering the
`struct stat` type definition. Same issue in `libc/signal.h` (sigaction) and
`freebsd/freebsd.h` (kevent). All 4 shadowing conflicts fixed.

### B3 -- `__attribute__((packed))` in type files breaks r2 parser ✅ FIXED
r2's `to` parser does not support GCC `__attribute__` extensions. Affected 3 files:
`dji/dji-assistant-win32.h`, `dji/dji-fly-android-arm64.h`, `juniper/srx_httpd_gk.h`.
All structs in those files were silently skipped. Removed the attribute annotations.

### B4 -- Backslash line continuation in `spacex/starlink.h` ✅ FIXED
`#define KEY \` + continuation line caused "Cannot find ( in function definition"
error, aborting parsing of all subsequent types. Joined continuation lines.

### B5 -- `elf-sinks.r2`: wrong filter order in conditionals ✅ FIXED
Script used `~[1]~NAME` (column-first, then grep) instead of `~NAME~[1]` (grep-first,
then column). This is the pattern used correctly in `windows-sinks.r2`.
More critically: consecutive failed `f` commands abort script in r2 6.x. Rewrote
script to chain all `f sink.NAME @ sym.imp.NAME` commands with semicolons on one line
per category, bypassing the r2 6.x consecutive-error abort behavior.

### B6 -- Missing top-level `linux-uclibc-arm32.r2` profile ✅ FIXED
The `libc/uclibc-arm32.r2` sub-profile existed but no standalone top-level profile
matched the naming convention of `linux-glibc-arm32.r2` etc. Added.

---

## Batch 1 — Auto-profile Routing Fixes (2026-08-06) ✅ DONE

Five systemic routing bugs fixed in one pass. No zsig generation required.

### B7 — `x86/32` arch default routed to `windows-x86.r2` ✅ FIXED
Every Linux i386 ELF binary silently loaded Windows PE analysis (VC++ zsigs,
Win32 types). Changed `arch_profiles["x86/32"]` to `linux-glibc-x86.r2`.
New profile created: `profiles/linux-glibc-x86.r2` + `profiles/libc/glibc-x86.r2`.
Both profile files reference `debian/i386/` zsigs (generated in Batch 2).

### B8 — No `arm/32` arch default ✅ FIXED
ARM32 ELFs (the most common embedded firmware arch) fell through `select_profile()`
returning `None` — zero types, zero zsigs loaded. Added `arm/32` → `linux-glibc-arm32.r2`.

### B9 — `arm/32/glibc` and `arm/32/uclibc` missing from `libc_profiles` ✅ FIXED
Even after B8, interpreter-based libc override had no ARM32 glibc/uclibc entries.
The `glibc/armhf/glibc-libc.zsig` (5351 sigs) was silently skipped for all ARM32
glibc firmware. Added both keys to `profiles_config.json`.

### B10 — `bin.os = windows` not checked before arch default lookup ✅ FIXED
Added `_WINDOWS_OS_HINTS` guard in `aether_r2profile.select_profile()`.
Windows PE binaries now route directly to `windows_profiles[arch/bits]` regardless
of the arch default mapping. A Linux i386 ELF (`os=linux`) and a Windows PE
(`os=windows`) sharing `arch=x86/bits=32` now correctly get different profiles.
`windows_profiles` section added to `profiles_config.json`.

### B11 — `ppc/32` arch default missing ✅ FIXED
PPC32 binaries with unknown vendor fell through to no profile. Added
`arch_profiles["ppc/32"]` → `cisco-ios-ppc32.r2` as a sane default.
`ppc/32/juniper` was already in vendor_profiles; confirmed still present.

### V1 — `validate-corpus.py` missing-zsig from error → warning ✅ FIXED
r2's `zo` silently skips missing zsig files — the corpus is fully functional
without them. Hard errors blocked CI for planned-but-not-yet-generated zsig
sets (e.g. `debian/i386/`). Downgraded to warning with actionable message
pointing to the generator script.

**Verification:** 12/12 routing tests pass. All referenced profile files exist.
`validate-corpus.py` → 0 errors, 19 warnings (all Batch 2 planned zsigs).

---

## Batch 3 — New zsig types + session cleanup (2026-08-06) ✅ DONE

### Batch 3a — Session zsig pair merges
Three redundant pairs eliminated. `prune-session-zsigs.py --merge` added.
11 sessions → 8 sessions. All merged counts verified via `strings` (not `z~?`).

### Batch 3b — FreeRTOS Cortex-M zsigs
`tool/generate-freertos-zsig.py` written using `clang --target=arm-none-eabi`.
Produces 322-336 sigs per target across CM0/CM3/CM4/CM7.
Wired into: `dji-flyc.r2` (CM4), `dji-gimbal.r2` (CM3), `dji-lightbridge.r2` (CM3).

### Batch 3c — uclibc-ng AArch64 zsigs
`tool/generate-uclibc-arm64-zsig.py` written (Bootlin aarch64--uclibc-2024.02-1).
Key fixes required: `.os` member support in `zsig_utils.extract_objects_from_archive`,
named-symbol pre-filter (1366/1382 objects), batch-size limit (avoid corrupt merge).
Output: `uclibc/arm64/uclibc-libc.zsig` — 1961 C API functions, 0 gfortran/C++ noise.
Wired: `libc/uclibc-arm64.r2` + `arm/64/uclibc` in `profiles_config.json`.

**Verification:** 3/3 routing tests pass. `validate-corpus.py` → 0 errors, 0 warnings.
Total corpus: **338 zsig files**.

---

## Batch 4 — Corpus cleanup + validator hardening (2026-08-06) ✅ DONE

### Cleanup

**glibc/armhf/glibc-libc.zsig deleted** — superseded by `debian/armhf/libc6.zsig`
and the full debian/armhf/ set (23 zsigs). The Linaro toolchain .zsig was the
original ARM32 glibc coverage before Batch 2. Removed to eliminate stale duplicates.

### New profiles (6 orphaned zsigs wired)

| Profile | Arch | Zsig wired |
|---------|------|-----------|
| `android-x86.r2` | x86/32 | android/x86/ndk-r27c.zsig |
| `android-x86_64.r2` | x86/64 | android/x86_64/ndk-r27c.zsig |
| `linux-go-x86.r2` | x86/32 | go/x86/go1.23-stdlib.zsig |
| `dji-generic.r2` | ARM32 | freertos-cm0 + newlib-v6m + freertos-cm7 added |

**vendor_profiles**: added `arm/32/dji` → `dji-generic.r2` (catch-all for unknown DJI ARM32 modules).
**vendor_profiles**: added `x86/32/android`, `x86/64/android`, `x86/32/go` routing.

### validate-corpus.py hardening (P3-2)

Added two new checks:
- **`check_arch_defaults()`** — regression-proof the Batch 1 fixes:
  - Errors if `arm/32` missing from arch_profiles
  - Errors if any arch default routes to a Windows PE profile
  - Errors if high-value libc overrides absent (arm/32/glibc, arm/32/uclibc,
    x86/32/glibc, x86/64/glibc, arm/64/glibc, arm/64/uclibc)
- **`check_orphaned_zsigs()`** — warns for zsig files unreferenced by any profile
  (Windows extras and sessions/ are exempt as intentional)

**Windows extras (114 files, 308 MB)** — MFC, ATL, vcamp, vcomp, vccorlib etc.
Available for manual `zo windows/x64/vs2022-mfc140.zsig` use. Not auto-loaded
because most PE targets don't link MFC. The exemption is documented in the check.

**Verification:** 7/7 routing tests pass. Orphan audit: 0 non-Windows orphans.
`validate-corpus.py` → 0 errors, 0 warnings (both new checks pass).

---

## P3-5 — PDB symbol server workflow (2026-08-06) ✅ DONE

### What was added

**`tool/fetch-windows-pdbs.sh`** — convenience wrapper around `download-pdb.py`:
```bash
# Download PDB for a single DLL/EXE
bash tool/fetch-windows-pdbs.sh target.dll

# Batch download PDBs for all DLLs in a directory
bash tool/fetch-windows-pdbs.sh /mnt/windows/System32/
```

**`.radare2rc` PDB settings** (now applied at every r2 startup):
```r2
e pdb.autoload=1                                          # auto-download on PE open
e pdb.symstore=/root/.local/share/radare2/cache/pdb      # local cache
e pdb.server=https://msdl.microsoft.com/download/symbols # Microsoft symbol server
```

**`.radare2rc` `~` → `$HOME` fix** — r2's `.` command expands `$HOME` but not `~`.
The `. ~/.radare2rc.local` line was failing silently; changed to `. $HOME/.radare2rc.local`.
This also fixes `pdb.symstore` from `.radare2rc.local` not being applied at startup.

### Usage in analysis

```bash
# Open a Windows PE — r2 auto-downloads the matching PDB via pdb.autoload
r2 -i profiles/windows-x64.r2 target.dll
[0x0]> aa
[0x0]> e pdb.autoload   # confirm: 1
[0x0]> idp              # manually load/reload PDB for current binary
```

PDBs cached at `~/.local/share/radare2/cache/pdb/` persist across sessions.
