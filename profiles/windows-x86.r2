# Windows x86 (32-bit) PE Analysis Profile
# Loads VC++ runtime signatures, Windows type definitions, and security sinks.
#
# Usage: r2 -i profiles/windows-x86.r2 target.exe
#        Or from r2: . profiles/windows-x86.r2
# Auto-selected by r2_profile_cmds.py when bintype=pe and bits=32.

# ── Architecture settings ────────────────────────────────────────────────────
e asm.arch=x86
e asm.bits=32
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

# ── Load Windows type definitions ──────────────────────────────────────────────────────────────────────────────
# dir.types is set in .radare2rc; these paths resolve relative to it.
to windows/functions.h
to windows/structs.h
to windows/functions-zsig.h
to windows/constants.h
to windows/win32-security-sinks.h
to windows/ntstatus.h
to windows/winerror.h

# ── Load VC++ runtime signatures ─────────────────────────────────────────────
# Named files first (provide real function names); pattern-only files after.
# msvcp140:    C++ stdlib (std::string, vector, streams)  -- 30-31% named
# concrt140:   Concurrency Runtime (thread pool, tasks)   -- 12-14% named
# vccorlib:    WinRT / C++/CX runtime types               -- 12-13% named
# vcruntime140 / ucrtbase: core CRT + UCRT               -- 0% named (pattern)
zo windows/x86/vs2022-msvcp140.zsig
zo windows/x86/vs2022-concrt140.zsig
zo windows/x86/vs2022-vccorlib140.zsig
zo windows/x86/vs2019-msvcp140.zsig
zo windows/x86/vs2019-concrt140.zsig
zo windows/x86/vs2019-vccorlib140.zsig
zo windows/x86/vs2017-msvcp140.zsig
zo windows/x86/vs2017-concrt140.zsig
zo windows/x86/vs2017-vccorlib140.zsig
zo windows/x86/vs2015-msvcp140.zsig
zo windows/x86/vs2015-concrt140.zsig
zo windows/x86/vs2015-vccorlib140.zsig
zo windows/x86/vs2013-vccorlib120.zsig
zo windows/x86/vs2012-vccorlib110.zsig
zo windows/x86/vs2022-vcruntime140.zsig
zo windows/x86/vs2019-vcruntime140.zsig
zo windows/x86/vs2017-ucrtbase.zsig
zo windows/x86/vs2015-ucrtbase.zsig
zo windows/x86/vs2015-vcruntime140.zsig
zo windows/x86/vs2013-msvcr120.zsig
zo windows/x86/vs2012-msvcr110.zsig
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

# ── x86 calling convention note ──────────────────────────────────────────────
# 32-bit Windows uses stdcall (callee cleans stack) or cdecl (caller cleans).
# r2ghidra handles both; check CC annotations after aaft.

# ── Post-load summary ────────────────────────────────────────────────────────
# After this profile loads:
#   f~sink          -- list all flagged sinks
#   f~entry         -- list detected entry points
#   axt sink.recv   -- find all recv callers
#   z/              -- (re)apply zsig signatures
#   aaft            -- propagate type info to matched functions
#   r2_vuln_scan    -- full xref-based sink callsite scan (from pi)