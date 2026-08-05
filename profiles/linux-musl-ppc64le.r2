# Linux PowerPC 64-bit LE with musl libc Analysis Profile
# For Alpine Linux ppc64le binaries, IBM Power servers running Alpine/musl,
# OpenPOWER workstations, and PowerPC 64-bit LE embedded targets.
#
# Architecture: POWER8/POWER9/POWER10 (ppc64le = little-endian ELFv2 ABI)
# Common targets: IBM Power servers, RaptorCS TALOS II/Blackbird, QEMU ppc64le
#
# Usage: r2 -i profiles/linux-musl-ppc64le.r2 binary
#        Or from r2: . profiles/linux-musl-ppc64le.r2

# Architecture settings
e asm.arch=ppc
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
e zign.mincc=1
e zign.minsz=4

# Load musl type definitions
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h

# Load musl ppc64le signatures (Alpine generic build)
zo musl/ppc64le/musl-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading:
#   aa     -- full analysis
#   z/     -- apply musl signatures
#   aaft   -- propagate type info
