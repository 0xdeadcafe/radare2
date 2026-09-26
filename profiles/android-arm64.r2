# Android Native (arm64-v8a) Analysis Profile
# Loads NDK libc signatures for stripped native binaries
#
# Usage: r2 -i profiles/android-arm64.r2 libnative.so
#        Or from r2: . profiles/android-arm64.r2

# Architecture settings
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

# Analysis settings
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true

# Zignature settings
e zign.graph=true
e zign.refs=true
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4

# Load Android type definitions
e dir.types=~/.local/share/radare2/types
to android/jni.h
to android/functions.h
to android/log.h
to android/asset.h
to libc/functions.h
to libc/socket.h

# Load NDK signatures (libc, libm, libc++)
# zo uses dir.zigns as base; ~ is expanded by r2
zo android/arm64-v8a/ndk-r27c.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading, run analysis:
#   aa      - Full analysis (aaa only for stripped <5 MB binaries)
#   z/      - Apply signatures to functions
