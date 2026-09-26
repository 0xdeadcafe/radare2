# OpenWrt MIPSEL MIPS32 (bcm47xx) Analysis Profile
# Target:  bcm47xx/generic — Broadcom BCM47xx SoC family
# CPU:     MIPS32, little-endian, soft-float (BCM47xx has no FPU)
# OS:      Linux (musl libc, OpenWrt 24.10.6)
# Source:  openwrt-toolchain-24.10.6-bcm47xx-generic_gcc-13.3.0_musl
#
# Common hardware:
#   Linksys WRT54G/WRT54GL/WRT160N, Netgear WGR614/WNR1000,
#   Asus WL-500gP v2, Buffalo WHR-G54S, many classic SOHO routers
#
# Note:
#   BCM47xx uses MIPS32 rev1 (not r2). No FPU — soft-float only.
#   The bcm47xx/mips74k subtarget (e.g. WNR3500L) uses the same LE ABI
#   but a faster MIPS 74Kc core; this profile covers both adequately.
#
# Usage:
#   r2 -i profiles/openwrt-mipsel_mips32.r2 binary
#   Or from r2 prompt: . profiles/openwrt-mipsel_mips32.r2

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

zo openwrt/mipsel_mips32/musl-libc.zsig

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
# BCM47xx memory layout:
#   DRAM:      0x00000000 (physical) / 0x80000000 kseg0
#   Flash:     0xbfc00000 (kseg1, 4 MB typical NOR)
#   u-boot:    0xbfc00000
#   kernel:    decompressed to 0x80000000 by CFE/u-boot
#
# These routers commonly use CFE (Common Firmware Environment) as bootloader
# instead of u-boot; CFE may be at the top of flash.
#
# Many BCM47xx firmwares are distributed as LZMA-compressed TRX images:
#   TRX magic: 48445230 (HDR0)
#   Structure: [TRX header][kernel.lzma][rootfs.squashfs]
#
# For raw kernel blob: r2 -m 0x80000000 -b 32 kernel.bin
# Then: . profiles/openwrt-mipsel_mips32.r2
#
# =============================================================================

# =============================================================================
# Workflow
#
# 1. TRX/firmware container extraction:
#      binwalk -e firmware.bin    (external tool)
#      /x 48445230                # TRX magic in r2
#      /x fd377a585a00            # XZ/LZMA magic
#
# 2. Triage extracted ELF:
#      rabin2 -I vmlinux
#      rabin2 -z vmlinux | grep -i 'version\|bcm\|broadcom' | head -10
#
# 3. Full analysis:
#      aaa
#
# 4. Apply signatures:
#      z/
#      afln~musl
#
# 5. BCM47xx-specific:
#      # NVRAM at 0xbfc00000 + (flash_size - 0x8000) — check top of flash
#      # wl (wireless) driver globals often at fixed BSS addresses
#      # CFE entrypoint: 0xbfc00000
#
# 6. Soft-float: no FPU instructions; float ops go through libgcc __addsf3 etc.
#      afln~__addsf3   # find soft-float calls after z/
# =============================================================================
