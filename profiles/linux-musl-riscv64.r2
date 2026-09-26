# Linux RISC-V 64-bit with musl libc Analysis Profile
# For Alpine Linux RISC-V 64-bit binaries, SiFive/StarFive boards (VisionFive 2),
# QEMU RISC-V emulation targets, and RISC-V embedded Linux.
#
# Architecture: RV64GC (RISC-V 64-bit, general + compressed instruction sets)
# ABI: LP64D (64-bit longs, hardware double-float)
# Common firmware: VisionFive 2 board, Milk-V Pioneer, QEMU virt
#
# Usage: r2 -i profiles/linux-musl-riscv64.r2 binary
#        Or from r2: . profiles/linux-musl-riscv64.r2

# Architecture settings
e asm.arch=riscv
e asm.bits=64
e cfg.bigendian=false

# PLT/GOT resolution
e bin.plt.resolve=true

# Analysis settings
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true

# Zignature settings
e zign.graph=true
e zign.refs=true
# Lower thresholds -- default mincc=10 kills simple RISC-V musl syscall wrappers
e zign.mincc=1
e zign.minsz=4

# Load musl type definitions
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h

# Load musl riscv64 signatures (Alpine generic build)
zo musl/riscv64/musl-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading:
#   aa     -- full analysis
#   z/     -- apply musl signatures
#   aaft   -- propagate type info
