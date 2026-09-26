# OpenWrt MIPS64 Octeon+ Analysis Profile
# Target:  octeon/generic — Cavium Octeon / OcteonPlus SoC family
# CPU:     MIPS64r2 + Cavium extensions, big-endian, hard-float, 64-bit
# OS:      Linux (musl libc, OpenWrt 24.10.6)
# Source:  openwrt-toolchain-24.10.6-octeon-generic_gcc-13.3.0_musl
#
# Common hardware:
#   Ubiquiti EdgeRouter Lite (ERLite-3), EdgeRouter 4 (ER-4),
#   EdgeRouter 6P (ER-6P), Ubiquiti EdgePoint series,
#   Cavium CN5xxx/CN6xxx evaluation boards
#
# Note on Cavium extensions:
#   Octeon+ adds ~70 non-standard instructions (crypto, SIMD, I/O).
#   r2's MIPS disassembler handles standard MIPS64r2 correctly but will
#   show Cavium-specific opcodes as raw bytes or incorrect mnemonics.
#   Known Cavium extensions: DMUL/DMULHI, BADDU, POP, DPOP, LBX, ...
#   If you see frequent decode failures in hot paths, cross-check with
#   Cavium's ISA supplement (MIPS Octeon Programmer's Guide).
#
# Usage:
#   r2 -i profiles/openwrt-mips64_octeonplus.r2 binary
#   Or from r2 prompt: . profiles/openwrt-mips64_octeonplus.r2

# =============================================================================
# Architecture
# =============================================================================
e asm.arch=mips
e asm.bits=64
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

zo openwrt/mips64_octeonplus/musl-libc.zsig

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
# Cavium Octeon memory layout (64-bit):
#   DRAM:       0x0000000000000000 (physical)
#   kseg0 (BE): 0xffffffff80000000 — 32-bit compat kernel (if any)
#   XKPHYS:     0x8000000000000000 | (attr<<59) — 64-bit physical access
#     Cached:   0x8000000000000000
#     Uncached: 0x9000000000000000
#   Kernel virtual: typically 0xffffffff80000000 for vmlinux
#
# EdgeRouter Lite kernel is typically a standard vmlinux ELF:
#   rabin2 -I /proc/kcore  (on a live unit)
#   On extracted firmware: vmlinux is usually uncompressed in the image
#
# For raw kernel blob: r2 -m 0xffffffff80000000 -b 64 -e cfg.bigendian=true vmlinux.bin
# Then: . profiles/openwrt-mips64_octeonplus.r2
#
# =============================================================================

# =============================================================================
# Workflow
#
# 1. EdgeRouter firmware is a standard Debian/OpenWrt hybrid (ERL) or
#    pure OpenWrt (ER-4/ER-6P on later releases).
#    Firmware format: squashfs + kernel in a standard image.
#    Extract: binwalk -e firmware.bin  (external)
#
# 2. Triage:
#      rabin2 -I vmlinux
#      rabin2 -z vmlinux | grep -iE 'octeon|cavium|ubiquiti|edgeos' | head -10
#      file vmlinux     # should show: ELF 64-bit MSB, MIPS
#
# 3. Full analysis (64-bit MIPS kernel, expect 30–120s):
#      aaa
#
# 4. Apply signatures:
#      z/
#      afln~musl
#
# 5. Cavium-specific:
#      # Hardware crypto: cavium_crypto_* functions — look for OCTEON_IS_MODEL()
#      # Fast I/O: uses Octeon work queues, PKO/PKI for packet processing
#      # /iz ~octeon; /iz ~cavium     # identify subsystem
#      # Cavium opcodes that r2 may misidentify: DMULHI, BADDU, LBX, SNAP
#      # Cross-reference suspect addresses with Cavium ISA guide
#
# 6. n32 ABI note:
#      # OpenWrt octeon/generic uses the 64-bit (n64) ABI.
#      # Some older Cavium userland (EdgeOS) used n32 — if addresses look
#      # 32-bit masked despite 64-bit ELF class, suspect n32 objects.
#      # n32 uses 64-bit regs but 32-bit pointers. Rare in OpenWrt context.
# =============================================================================
