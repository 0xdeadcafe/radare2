# OpenWrt MIPS MIPS32 (bmips/bcm63xx) Analysis Profile
# Target:  bmips/bcm6358 — Broadcom BCM63xx xDSL SoC family
# CPU:     MIPS32, big-endian, soft-float
# OS:      Linux (musl libc, OpenWrt 24.10.6)
# Source:  openwrt-toolchain-24.10.6-bmips-bcm6358_gcc-13.3.0_musl
#
# Common hardware:
#   BT HomeHub 2B/3A, Orange Livebox 2, Netgear DG834,
#   Technicolor TG582n/TG789, Sagem F@ST 2704, BCM6358/BCM6368-based DSL modems
#
# Note:
#   BMIPS (Broadcom MIPS) is big-endian MIPS32 rev1 without an FPU.
#   DSL modems in this family typically run a vendor-modified Linux with
#   proprietary DSL PHY and ATM/PTM stack as kernel modules.
#   The `bmips/bcm6318` subtarget (BCM6318/BCM63268) uses the same ABI
#   and this profile applies there too.
#
# Usage:
#   r2 -i profiles/openwrt-mips_mips32.r2 binary
#   Or from r2 prompt: . profiles/openwrt-mips_mips32.r2

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

zo openwrt/mips_mips32/musl-libc.zsig

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
# Memory map notes
#
# BCM6358 memory layout:
#   DRAM:      0x00000000 (physical) / 0x80000000 kseg0
#   Flash:     0xbfc00000 (kseg1, NOR or NAND depending on model)
#   CFE:       0xbfc00000 (Broadcom CFE bootloader)
#   Kernel:    decompressed to 0x80010000 (typical for BCM63xx)
#
# BCM63xx firmware image format (CFE-based):
#   Magic: 33 30 30 31  ("3001") or similar vendor tag
#   Contains: [CFE header][kernel][rootfs]
#
# Vendor firmwares often use squashfs or cramfs for rootfs.
# The kernel ELF/vmlinux may be LZMA-compressed inside the image.
#
# For raw kernel blob: r2 -m 0x80010000 -b 32 -e cfg.bigendian=true kernel.bin
# Then: . profiles/openwrt-mips_mips32.r2
#
# =============================================================================

# =============================================================================
# Workflow
#
# 1. DSL modem firmware often has vendor-specific container formats.
#    Check magic bytes first:
#      /m                       # magic scan (gzip, squashfs, cramfs, lzma)
#      rahash2 -b 512 -a entropy firmware.bin   # entropy map for compressed blobs
#
# 2. Many BCM63xx vendor builds use uclibc (older) or musl (OpenWrt).
#    Confirm C library:
#      rabin2 -z binary | grep -iE 'musl|uclibc|glibc'
#
# 3. Triage:
#      rabin2 -I binary
#
# 4. Full analysis:
#      aaa
#
# 5. Apply signatures:
#      z/
#      afln~musl
#
# 6. BCM63xx-specific:
#      # DSL driver globals typically in fixed BSS (look for xDSL/ADSL strings)
#      # /iz ~xdsl; /iz ~adsl; /iz ~vdsl
#      # Proprietary modules loaded at runtime — only base system is in flash ELF
#      # Soft-float: float through libgcc, same as bcm47xx above
# =============================================================================
