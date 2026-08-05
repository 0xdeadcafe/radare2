# Linux ARM32 ARMv7 with musl libc Analysis Profile
# For Alpine Linux ARMv7 (armv7) binaries — distinct from armhf in musl's
# ABI (armv7 softfp calling convention vs armhf hardfp).
# Covers Cortex-A7/A9/A15 targets compiled for ARMv7 musl.
#
# Usage: r2 -i profiles/linux-musl-armv7.r2 binary
#        Or from r2: . profiles/linux-musl-armv7.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# PLT→GOT resolution
e bin.plt.resolve=true

# Analysis settings
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true

# Zignature settings
e zign.graph=true
e zign.refs=true
# Lower matching thresholds — default mincc=10 kills simple syscall wrappers (1 BB)
e zign.mincc=1
e zign.minsz=4

# Load musl type definitions
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h

# Load musl ARMv7 signatures
zo musl/armv7/musl-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading, run analysis:
#   aa      - Full analysis
#   z/      - Apply signatures to functions
