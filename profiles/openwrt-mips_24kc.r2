# OpenWrt MIPS 24Kc (ath79) Analysis Profile
# Target:  ath79/generic — Atheros AR7xxx/AR9xxx SoC family
# CPU:     MIPS 24Kc, MIPS32r2, big-endian, hard-float
# OS:      Linux (musl libc, OpenWrt 24.10.6)
# Source:  openwrt-toolchain-24.10.6-ath79-generic_gcc-13.3.0_musl
#
# Common hardware:
#   TP-Link WR841N/WR1043ND/Archer C7, GL-iNet GL-AR150/AR300M,
#   Netgear WNDR3700, Ubiquiti NanoStation M-series, Mikrotik RB9xx
#
# Usage:
#   r2 -i profiles/openwrt-mips_24kc.r2 binary
#   Or from r2 prompt: . profiles/openwrt-mips_24kc.r2

# =============================================================================
# Architecture
# =============================================================================
e asm.arch=mips
e asm.bits=32
e cfg.bigendian=true
e asm.cpu=mips32/64

# =============================================================================
# Analysis
# =============================================================================
# MIPS has branch delay slots — the instruction after a branch always executes.
# anal.delay must be true or call/jump targets will be off by 4 bytes.
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

zo openwrt/mips_24kc/musl-libc.zsig

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
# MIPS virtual address regions:
#   kseg0  0x80000000–0x9fffffff  cached kernel   (mirrors physical 0x0–0x1fffffff)
#   kseg1  0xa0000000–0xbfffffff  uncached kernel  (same physical, used for MMIO)
#   kuseg  0x00000000–0x7fffffff  user space
#
# ath79 typical flash/RAM layout (AR9344 example):
#   u-boot:    0xbf000000 (KSEG1 NOR flash base)
#   kernel:    0x80060000 (loaded by u-boot, kseg0)
#   rootfs:    squashfs/jffs2 after kernel in flash
#
# For a raw kernel blob: r2 -m 0x80060000 -b 32 -e cfg.bigendian=true kernel.bin
# Then: . profiles/openwrt-mips_24kc.r2
#       e asm.arch=mips  (already set above, re-affirm after -m override)
#       aaa
#
# =============================================================================

# =============================================================================
# Workflow
#
# 1. Triage:
#      rabin2 -I binary
#      rabin2 -z binary | head -40
#      rahash2 -b 512 -a entropy binary   # spot compressed/encrypted sections
#
# 2. Confirm MIPS BE before analysis:
#      pd 4 @ entry0
#      # Should see: addiu / lui / lw patterns; NOT reversed bytes
#
# 3. Full analysis (static musl binary ~5–60s):
#      aaa
#
# 4. Apply signatures and check matches:
#      z/
#      afln~musl   # list musl-matched functions
#
# 5. MIPS-specific gotchas:
#      # Branch delay slots: instruction at branch+4 always runs
#      # e anal.delay=true handles this — do not disable
#
#      # MIPS GP register: many functions access globals via $gp.
#      # r2 does not auto-set $gp; set manually if globals look wrong:
#      # ar gp=0x<_gp_address_from_nm>
#
#      # PIC code (shared libs): jalr $t9 is the standard indirect call.
#      # axt $t9 won't help; trace callers via axt on the actual function.
#
# 6. Useful searches on router firmware:
#      /iz ~password          # strings containing "password"
#      /x 7f454c46            # nested ELF headers (packed userland)
#      /m                     # magic scan (squashfs, gzip, uImage headers)
# =============================================================================
