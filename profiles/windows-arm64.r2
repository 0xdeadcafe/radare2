# Windows ARM64 PE Analysis Profile
# Loads VC++ runtime signatures, Windows type definitions, and security sinks.
#
# Usage: r2 -i profiles/windows-arm64.r2 target.exe
#        Or from r2: . profiles/windows-arm64.r2
# Auto-selected by r2_profile_cmds.py when bintype=pe and bits=64 and arch=arm.

# ── Architecture settings ────────────────────────────────────────────────────
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

# ── Analysis settings ────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true
e anal.trycatch=true       # Detect SEH / C++ exception handlers (common in PE)

# AArch64 pointer authentication — Windows on ARM uses PACIA/RETAA
# r2 strips PAC bits automatically; this enables correct branch analysis
e anal.jmp.indir=true

# ── Zignature quality flags ──────────────────────────────────────────────────
e zign.graph=true
e zign.refs=true
e zign.types=true
# Match small stub functions (1 BB) that VC++ runtime uses heavily
e zign.mincc=1
e zign.minsz=4

# ── Load Windows type definitions ───────────────────────────────────────────
e dir.types=~/.local/share/radare2/types
to windows/functions.h
to windows/structs.h
to windows/functions-zsig.h
to windows/constants.h
to windows/win32-security-sinks.h
to windows/ntstatus.h
to windows/winerror.h

# ── Load VC++ runtime signatures ─────────────────────────────────────────────
# zo uses dir.zigns as base (set by install.sh / .radare2rc.local)
# Coverage: VS2019 and VS2022 arm64 runtimes
zo windows/arm64/vs2022-vcruntime140.zsig
zo windows/arm64/vs2022-vcruntime140_1.zsig
zo windows/arm64/vs2022-msvcp140.zsig
zo windows/arm64/vs2022-msvcp140_1.zsig
zo windows/arm64/vs2022-msvcp140_2.zsig
zo windows/arm64/vs2022-msvcp140_atomic_wait.zsig
zo windows/arm64/vs2022-msvcp140_codecvt_ids.zsig
zo windows/arm64/vs2022-concrt140.zsig
zo windows/arm64/vs2022-vcamp140.zsig
zo windows/arm64/vs2022-vcomp140_system.zsig
zo windows/arm64/vs2022-vccorlib140.zsig
zo windows/arm64/vs2019-vcruntime140.zsig
zo windows/arm64/vs2019-vcruntime140_1.zsig
zo windows/arm64/vs2019-msvcp140.zsig
zo windows/arm64/vs2019-msvcp140_1.zsig
zo windows/arm64/vs2019-msvcp140_2.zsig
zo windows/arm64/vs2019-msvcp140_atomic_wait.zsig
zo windows/arm64/vs2019-msvcp140_codecvt_ids.zsig
zo windows/arm64/vs2019-concrt140.zsig
zo windows/arm64/vs2019-vcamp140.zsig
zo windows/arm64/vs2019-vcomp140.zsig
zo windows/arm64/vs2019-vccorlib140.zsig

# ── MFC (VS2022 arm64 only) ──────────────────────────────────────────────────
zo windows/arm64/vs2022-mfcm140.zsig
zo windows/arm64/vs2022-mfcm140u.zsig

# ── Visual settings ──────────────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.var=true

# ── Security sink labeling ────────────────────────────────────────────────────
. /usr/local/share/radare2/scripts/windows-sinks.r2

# ── Post-load summary ────────────────────────────────────────────────────────
# After this profile loads:
#   f~sink          -- list all flagged sinks
#   f~entry         -- list detected entry points
#   axt sink.recv   -- find all recv callers
#   z/              -- (re)apply zsig signatures
#   aaft            -- propagate type info to matched functions
