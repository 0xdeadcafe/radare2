# Android Native (x86_64) Analysis Profile
# Loads NDK libc signatures for x86_64 Android native binaries.
# Targets: Android emulator (AVD x86_64), Chromebook native x86_64 apps,
#          CTF binaries built for x86_64 Android.
#
# Usage: r2 -i profiles/android-x86_64.r2 libnative.so
#        Or from r2: . profiles/android-x86_64.r2

# Architecture settings
e asm.arch=x86
e asm.bits=64
e cfg.bigendian=false

# PLT resolution
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

# Load Android type definitions
e dir.types=~/.local/share/radare2/types
to android/jni.h
to android/functions.h
to android/log.h
to android/asset.h
to libc/functions.h
to libc/socket.h

# Load NDK x86_64 signatures (libc, libm, libc++)
zo android/x86_64/ndk-r27c.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading:
#   aa      - Full analysis
#   z/      - Apply signatures to functions
