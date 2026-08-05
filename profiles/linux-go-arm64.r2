# Linux ARM64 Go binary analysis profile
# For stripped and non-stripped Go 1.18+ ELF binaries on Linux arm64.
#
# ARM64 Go note: goroutine pointer is in R28 (callee-saved by Go ABI).
#
# Usage: r2 -i profiles/linux-go-arm64.r2 binary
#        Or from r2: . profiles/linux-go-arm64.r2

# Architecture settings
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

e bin.plt.resolve=true
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=false

e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# Load Go runtime types
e dir.types=~/.local/share/radare2/types
to go/runtime.h

# Load Go stdlib signatures (Go 1.23, 40% named)
zo go/arm64/go1.23-stdlib.zsig

e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.var=true

# After loading:
#   aa       -- full analysis (pclntab recovery)
#   z/       -- apply stdlib signatures
