# Linux x86 (32-bit) with musl libc Analysis Profile
# For Alpine Linux binaries and other musl-based 32-bit x86 systems
#
# Usage: r2 -i profiles/linux-musl-x86.r2 binary
#        Or from r2: . profiles/linux-musl-x86.r2

# Architecture settings
e asm.arch=x86
e asm.bits=32
e cfg.bigendian=false

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

# Load musl libc x86 signatures
zo musl/x86/musl-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading, run analysis:
#   aa      - Full analysis (aaa only for stripped <5 MB binaries)
#   z/      - Apply signatures to functions
