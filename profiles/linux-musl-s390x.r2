# Linux s390x (IBM Z) with musl libc Analysis Profile
# For Alpine Linux s390x binaries, IBM Z / LinuxONE mainframe workloads,
# and s390x QEMU emulation targets.
#
# Architecture: IBM z/Architecture 64-bit (s390x), big-endian
# Registers: 16 x 64-bit GPRs, r15 = stack pointer
# Common targets: IBM Z mainframes, LinuxONE, Docker s390x CI runners
#
# Usage: r2 -i profiles/linux-musl-s390x.r2 binary
#        Or from r2: . profiles/linux-musl-s390x.r2

# Architecture settings
e asm.arch=s390
e asm.bits=64
e cfg.bigendian=true

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
e zign.mincc=1
e zign.minsz=4

# Load musl type definitions
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h

# Load musl s390x signatures (Alpine generic build)
zo musl/s390x/musl-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading:
#   aa     -- full analysis
#   z/     -- apply musl signatures
#   aaft   -- propagate type info
