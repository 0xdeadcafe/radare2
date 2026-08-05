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

### P1-5 Duplicate session zsigs from same source binary
Two pairs each come from the same binary but capture different analysis stages:
- `0d97def03812819a` (178 sigs) + `403d19d7c890fd17` (134 sigs) both from `76bb8697f3c8bec8`
- `6e9059417fa6324c` (35 sigs) + `daed52b867799857` (1319 sigs) both from `5716572fb55ea25f`
The smaller sessions are subsets. Loading both wastes time and risks false-positive
double-renames. **TODO**: Merge each pair via `rasign2 -m`; keep only the merged zsig.

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

### P2-4 Session `fc531267fc2f85a8`: ~33% unnamed (66 entries)
Netgear Orbi CGI session. About 22 entries are likely `fcn.*` names.
**TODO**: Run `python3 tool/prune-session-zsigs.py --keys fc531267fc2f85a8`.

### P2-5 Session `f29d5e39bd05d704`: ~33% unnamed (313 entries, IPMI OEM)
Has `fcn.0004edf0` and C++ mangled names mixed together.
**TODO**: Run `python3 tool/prune-session-zsigs.py --keys f29d5e39bd05d704`.

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
| Session pair merges (P1-5) | mixed | LOW | OPEN — needs rasign2 merge support |
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
python3 tool/prune-session-zsigs.py --r2dir . --keys de2cc34b9686e5da fc531267fc2f85a8 f29d5e39bd05d704

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

**TODO**: Create `profiles/juniper-ppc32.r2` mirroring `juniper-srx.r2` but with
`e asm.arch=ppc;e asm.bits=32`. Wire it to `profiles_config.json` and
`symbols/juniper/family_f5e1d8fb/`.

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
