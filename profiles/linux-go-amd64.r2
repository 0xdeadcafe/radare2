# Linux x86-64 Go binary analysis profile
# For stripped and non-stripped Go 1.18+ ELF binaries on Linux amd64.
#
# Go binaries >= 1.2 carry a pclntab that r2 uses to recover function names.
# This profile loads Go runtime type definitions and stdlib signatures for
# deeper analysis when pclntab is absent or for annotating heap/stack data.
#
# Usage: r2 -i profiles/linux-go-amd64.r2 binary
#        Or from r2: . profiles/linux-go-amd64.r2
#
# Quick orientation after aa:
#   iz~go.build   -- Go version and build info
#   f~go.         -- Go runtime flags (goroutine start, panic hooks, etc.)
#   axt sym.runtime.gopanic  -- find all panic call sites
#   axt sym.runtime.newproc  -- find all goroutine launches (go keyword)

# Architecture settings
e asm.arch=x86
e asm.bits=64
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

# Load Go stdlib signatures (Go 1.23, 87% named)
zo go/amd64/go1.23-stdlib.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.var=true

# After loading:
#   aa       -- full analysis (recovers Go function names from pclntab)
#   z/       -- apply stdlib signatures (finds more funcs in stripped builds)
#   axt sym.runtime.newproc  -- all goroutine launches
#   axt sym.runtime.gopanic  -- all panic sites
#   tsc go_g -- inspect goroutine descriptor layout at runtime.allgs
