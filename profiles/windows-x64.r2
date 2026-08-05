# Windows x64 PE Analysis Profile
# Loads VC++ runtime signatures, Windows type definitions, and security sinks.
#
# Usage: r2 -i profiles/windows-x64.r2 target.exe
#        Or from r2: . profiles/windows-x64.r2
# Auto-selected by r2_profile_cmds.py when bintype=pe and bits=64.

# ── Architecture settings ────────────────────────────────────────────────────
e asm.arch=x86
e asm.bits=64
e cfg.bigendian=false

# ── Analysis settings ────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true
e anal.trycatch=true       # Detect SEH / C++ exception handlers (common in PE)

# ── Zignature quality flags ──────────────────────────────────────────────────
e zign.graph=true
e zign.refs=true
e zign.types=true
# Lower matching thresholds — default mincc=10 kills simple CRT stubs (1 BB)
e zign.mincc=1
e zign.minsz=4

# ── Load Windows type definitions ───────────────────────────────────────────
# dir.types is set in .radare2rc; these paths resolve relative to it.
to windows/functions.h
to windows/structs.h
to windows/functions-zsig.h
to windows/constants.h
to windows/win32-security-sinks.h
to windows/ntstatus.h
to windows/winerror.h

# ── Load VC++ runtime signatures ─────────────────────────────────────────────
# zo uses dir.zigns as base (set by install.sh / .radare2rc.local)
#
# Zsig quality note (measured 2026-08-05):
#   Named sigs = entries with real function names (not fcn.XXXXXXXX).
#   0%-named files still help identify library boundaries via pattern matching;
#   named files additionally provide actual function names after z/.
#
# Named files loaded first so they can set realnames before unnamed matches.
#
# msvcp140:    C++ stdlib (std::string, vector, streams)      -- 31-37% named
# concrt140:   Concurrency Runtime (thread pool, tasks)       -- 15-17% named
# vccorlib140: WinRT/C++/CX types                            -- 13-19% named
# msvcp140_2:  Extended C++ stdlib (charconv, regex, etc.)   -- 0% named (pattern)
# vcruntime140: core CRT exception handling / memcpy         -- 0% named (pattern)
# ucrtbase:    Universal CRT (printf, fopen, etc.)           -- 0% named (pattern)
zo windows/x64/vs2022-msvcp140.zsig
zo windows/x64/vs2022-concrt140.zsig
zo windows/x64/vs2022-vccorlib140.zsig
zo windows/x64/vs2019-msvcp140.zsig
zo windows/x64/vs2019-concrt140.zsig
zo windows/x64/vs2019-vccorlib140.zsig
zo windows/x64/vs2017-msvcp140.zsig
zo windows/x64/vs2017-concrt140.zsig
zo windows/x64/vs2017-vccorlib140.zsig
zo windows/x64/vs2015-msvcp140.zsig
zo windows/x64/vs2015-concrt140.zsig
zo windows/x64/vs2015-vccorlib140.zsig
zo windows/x64/vs2013-vcruntime.zsig
zo windows/x64/vs2012-vcruntime.zsig
zo windows/x64/vs2022-vcruntime140.zsig
zo windows/x64/vs2019-vcruntime140.zsig
zo windows/x64/vs2019-msvcp140_2.zsig
zo windows/x64/vs2017-ucrtbase.zsig
zo windows/x64/vs2015-ucrtbase.zsig
zo windows/x64/vs2015-vcruntime140.zsig
zo windows/x64/vs2013-msvcr120.zsig
zo windows/x64/vs2012-msvcr110.zsig

# ── Visual settings ──────────────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.var=true

# ── Security sink labeling — runs automatically on profile load ──────────────
# windows-sinks.r2 is a native r2 script (no Python, no external tools).
# It uses the ?l + ?ne + macro pattern to flag dangerous imports as sink.*
# and detect entry points as entry.* flags.
#
# This line sources it automatically AFTER aa/aaa has completed
# (r2_open runs init_cmds first, then the profile is sourced):
. /usr/local/share/radare2/scripts/windows-sinks.r2

# ── Post-load summary ────────────────────────────────────────────────────────
# After this profile loads:
#   f~sink          -- list all flagged sinks
#   f~entry         -- list detected entry points
#   axt sink.recv   -- find all recv callers
#   z/              -- (re)apply zsig signatures
#   aaft            -- propagate type info to matched functions
#   r2_vuln_scan    -- full xref-based sink callsite scan (from pi)
