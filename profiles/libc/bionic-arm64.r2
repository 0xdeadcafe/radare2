# libc/bionic-arm64.r2 — Android Bionic libc AArch64
#
# Targets:
#   Android native ARM64 binaries (arm64-v8a ABI)
#   intrp: /system/bin/linker64
#
# Source: zigns/android/arm64-v8a/ndk-r27c.zsig

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo android/arm64-v8a/ndk-r27c.zsig
e dir.types=~/.local/share/radare2/types
to android/jni.h
to android/functions.h
to android/log.h
to android/asset.h
to libc/functions.h
to libc/socket.h
