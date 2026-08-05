# libc/musl-arm64.r2 — musl libc AArch64 (Alpine Linux, OpenWrt arm64)
#
# Targets:
#   Alpine Linux ARM64 userland binaries
#   OpenWrt arm64 targets (e.g. RPi4, Qualcomm IPQ807x)
#   Any aarch64 binary built against musl (intrp: /lib/ld-musl-aarch64.so.1)
#
# Source: zigns/musl/aarch64/musl-libc.zsig
# Coverage: ~15,600 function signatures (musl 1.2.x full libc)
#
# NOT for glibc ARM64 (HPE iLO, Debian arm64) — use glibc-arm64.r2
# NOT for Android ARM64 (Bionic) — use bionic-arm64.r2

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo musl/aarch64/musl-libc.zsig
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
