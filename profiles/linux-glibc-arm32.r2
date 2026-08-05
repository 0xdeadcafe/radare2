# Linux ARM32 with glibc Analysis Profile
# For ARM32 Cortex-A binaries using glibc (Android NDK cross-compiled tools,
# older embedded Linux distributions, Raspberry Pi OS 32-bit).
#
# Usage: r2 -i profiles/linux-glibc-arm32.r2 binary
#        Or from r2: . profiles/linux-glibc-arm32.r2

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

# Load glibc type definitions
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h

# Load glibc ARM32 (armhf) signatures
zo glibc/armhf/glibc-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading, run analysis:
#   aa      - Full analysis
#   z/      - Apply signatures to functions
