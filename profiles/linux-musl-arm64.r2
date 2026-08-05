# Linux aarch64 with musl libc Analysis Profile
# For Alpine Linux binaries and other musl-based systems
#
# Usage: r2 -i profiles/linux-musl-arm64.r2 binary
#        Or from r2: . profiles/linux-musl-arm64.r2

# Architecture settings
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

# PLT→GOT resolution for AArch64 PIE
# iij .plt field is ground truth; aaef force-renames stubs; /ad bl finds callers.
# load_profile() in aether_r2profile.py calls aaef + resolve_aarch64_plt() automatically.
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

# Load musl libc signatures (zo uses dir.zigns as base; ~ is expanded by r2)
zo musl/aarch64/musl-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading, run analysis:
#   aa      - Full analysis (aaa only for stripped <5 MB binaries)
#   z/      - Apply signatures to functions
