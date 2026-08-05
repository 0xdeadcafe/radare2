# linux-uclibc-mips.r2 — Linux MIPS32 Big-Endian with uClibc Analysis Profile
#
# For OpenWrt/Barrier Breaker firmware and similar uClibc-based MIPS systems:
#   DJI Wi-Fi modules (P3C/P3S m0700, m2700)
#   General OpenWrt routers (MIPS32r2 + uClibc 0.9.33.x)
#
# This is the base MIPS arch profile.  Vendor-specific profiles (dji-wifi.r2,
# cobham-generic.r2) source this file first, then add their own types and symbols.
#
# Usage:
#   r2 -i profiles/linux-uclibc-mips.r2 binary
#   Or from r2: . profiles/linux-uclibc-mips.r2
#   Or sourced by dji-wifi.r2 / cobham-generic.r2 as their first line.
#
# After loading, run analysis:
#   aa      — basic analysis (recommended; use aaa only on stripped <5MB binaries)
#   z/      — apply loaded signatures
#   /m magic/crypto_tables.magic   — identify CRC/crypto lookup tables

# ── Architecture settings ─────────────────────────────────────────────────────
e asm.arch=mips
e asm.bits=32
e cfg.bigendian=true

# ── Analysis tuning for MIPS firmware ────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e anal.datarefs=true
e anal.jmp.indir=true

# ── Zignature settings ────────────────────────────────────────────────────────
e zign.graph=true
e zign.refs=true
# Lower matching thresholds — default mincc=10 kills simple functions
e zign.mincc=1
e zign.minsz=4

# ── Visual settings ───────────────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=55

# ── Type definitions — richer decompilation output ───────────────────────────
# Gives r2ghidra named function signatures (recv, send, socket, etc.) and
# struct types instead of raw pointer casts.
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h

# ── PLT stub resolution ───────────────────────────────────────────────────────
# NOTE: #!pipe is NOT called here because this profile is sourced inside r2pipe
# sessions (from aether_r2profile.load_profile()).  PLT resolution is handled
# programmatically by resolve_mips_plt(r2) in aether_r2profile.py, which is
# called automatically after this profile loads.
#
# For interactive standalone use (r2 opened directly, not via r2pipe), run:
#   . ~/.local/share/radare2/profiles/mips-plt-resolve.r2
# after aa completes.

# ── MIPS Big-Endian zignatures ───────────────────────────────────────────────
# zsigs are NOT loaded here — aether_r2profile.py detects the C library from
# the ELF intrp field and sources the correct libc layer profile automatically:
#   uClibc (ld-uClibc.so.0)  → profiles/libc/uclibc-mips32.r2
#   musl   (ld-musl-mips*.1) → profiles/libc/musl-mips32-be.r2
#   static/eCos (no intrp)   → no zsigs (avoid false positives)
# The previous `zo openwrt/mips_24kc/musl-libc.zsig` was wrong for uClibc
# targets (DJI firmware uses uClibc, not musl).  If you are sourcing this
# profile manually without load_profile(), call the libc layer explicitly:
#   . profiles/libc/uclibc-mips32.r2   # for DJI / uClibc
#   . profiles/libc/musl-mips32-be.r2  # for OpenWrt musl

# ── Magic scans — label crypto tables and identify protocol handlers ──────────
# Run after binary is loaded. Hits label the match address; axt finds callers.
/m /root/.local/share/radare2/magic/crypto_tables.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic
