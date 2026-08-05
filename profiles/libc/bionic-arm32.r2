# libc/bionic-arm32.r2 — Android Bionic libc ARM32
#
# Targets:
#   Android native ARM32 binaries (armeabi-v7a ABI)
#   intrp: /system/bin/linker

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo android/armeabi-v7a/ndk-r27c.zsig
e dir.types=~/.local/share/radare2/types
to android/jni.h
to android/functions.h
to android/log.h
to android/asset.h
to libc/functions.h
to libc/socket.h
