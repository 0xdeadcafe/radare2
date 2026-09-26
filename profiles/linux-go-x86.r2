# Linux x86 (32-bit) Go binary analysis profile
# For stripped and non-stripped Go 1.18+ ELF binaries on Linux x86/i386.
# Less common than amd64/arm64 but occurs in 32-bit container builds and
# legacy Go services compiled for i386.
#
# Usage: r2 -i profiles/linux-go-x86.r2 binary
#        Or from r2: . profiles/linux-go-x86.r2

# Architecture settings
e asm.arch=x86
e asm.bits=32
e cfg.bigendian=false

e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=false   # Go names are already human-readable

e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# Load Go runtime types
e dir.types=~/.local/share/radare2/types
to go/runtime.h

# Load Go stdlib signatures (Go 1.23, x86 32-bit)
zo go/x86/go1.23-stdlib.zsig

e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading:
#   aa       -- full analysis (pclntab recovery)
#   z/       -- apply stdlib signatures
