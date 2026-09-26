# OpenWrt MIPSEL 24Kc (ramips/mt7621) Analysis Profile
# Target:  ramips/mt7621 — MediaTek/Ralink MT7620 / MT7621 SoC family
# CPU:     MIPS 24Kc, MIPS32r2, little-endian, hard-float
# OS:      Linux (musl libc, OpenWrt 24.10.6)
# Source:  openwrt-toolchain-24.10.6-ramips-mt7621_gcc-13.3.0_musl
#
# Common hardware:
#   TP-Link TL-WR841N v13+/Archer C20/C50, Xiaomi Mi Router 3/3G,
#   ASUS RT-N14U/RT-AC51U, Netgear R6020, GL-iNet GL-MT300N-V2
#
# Note on microMIPS:
#   Some ramips devices (MT7620-based) ship firmware compiled with microMIPS.
#   If disassembly looks garbled, try: e asm.cpu=micro
#   MT7621 is standard MIPS32r2 (no microMIPS).
#
# Usage:
#   r2 -i profiles/openwrt-mipsel_24kc.r2 binary
#   Or from r2 prompt: . profiles/openwrt-mipsel_24kc.r2

# =============================================================================
# Architecture
# =============================================================================
e asm.arch=mips
e asm.bits=32
e cfg.bigendian=false
e asm.cpu=mips32/64

# =============================================================================
# Analysis
# =============================================================================
e anal.delay=true
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e anal.depth=64
e bin.demangle=true

# =============================================================================
# Zignatures
# =============================================================================
e zign.graph=true
e zign.refs=true
e zign.minscore=0.8
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4

zo openwrt/mipsel_24kc/musl-libc.zsig

# =============================================================================
# Type definitions (musl)
# =============================================================================
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h

# =============================================================================
# Display
# =============================================================================
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.xrefs=true
e asm.size=true

# =============================================================================
# Memory map notes (raw firmware blobs, not ELF)
#
# MT7621 memory layout:
#   DRAM:      0x00000000 (physical) / 0x80000000 kseg0 cached
#   NOR flash: 0xbc000000 (uncached, kseg1)
#   u-boot:    0xbc000000
#   kernel:    typically 0x80000000 or loaded by u-boot to RAM
#
# MT7620 layout is similar but RAM may differ (32–128 MB typical).
#
# For a raw kernel blob: r2 -m 0x80000000 -b 32 kernel.bin
# Then: . profiles/openwrt-mipsel_24kc.r2
#
# =============================================================================

# =============================================================================
# Workflow
#
# 1. Triage:
#      rabin2 -I binary
#      rabin2 -z binary | head -40
#      rahash2 -b 512 -a entropy binary
#
# 2. Confirm MIPS LE (bytes should read low-byte-first):
#      pd 4 @ entry0
#      # addiu sp, sp, -N  encodes as  XX XX bd 27  (0x27bd....)
#
# 3. Full analysis:
#      aaa
#
# 4. Apply signatures:
#      z/
#      afln~musl
#
# 5. microMIPS detection:
#      # If pd shows nonsense with mips32/64, the binary may be microMIPS.
#      # Switch with: e asm.cpu=micro
#      # Telltale: function addresses end in 1 (microMIPS symbol flag)
#      # Check: rabin2 -s binary | grep -c 'MIPS16\|micromips'
#
# 6. Common OpenWrt/ramips firmware artefacts:
#      /x 27051956            # u-boot legacy image magic (big-endian on-flash)
#      /x 68737173            # squashfs magic (LE: 73717368)
#      /m                     # full magic scan
#      /iz ~nvram             # NVRAM config strings
# =============================================================================
