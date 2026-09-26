# Linux ARM32 with musl libc Analysis Profile
# For Alpine Linux ARM32 binaries, BusyBox-based embedded systems, and
# other musl-based ARM32 targets (armhf / Cortex-A little-endian).
#
# Usage: r2 -i profiles/linux-musl-arm32.r2 binary
#        Or from r2: . profiles/linux-musl-arm32.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# PLT→GOT resolution for ARM32 PIE
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

# Load musl ARM32 (armhf) signatures
zo musl/armhf/musl-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading, run analysis:
#   aa      - Full analysis
#   z/      - Apply signatures to functions
