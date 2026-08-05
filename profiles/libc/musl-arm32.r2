# libc/musl-arm32.r2 — musl libc ARM32 (OpenWrt armv7/armhf, Alpine ARM32)
#
# Targets:
#   Alpine Linux ARMv7 userland
#   OpenWrt armv7 targets built with musl toolchain
#   Any ARM32 binary with intrp: /lib/ld-musl-armhf.so.1 or ld-musl-arm.so.1
#
# Source: zigns/musl/armv7/musl-libc.zsig (ARMv7 hard-float, most common)
#         zigns/musl/armhf/musl-libc.zsig (alternative ABI)
#
# NOT for uClibc ARM32 (Supermicro BMC, old embedded) — uclibc-arm32.r2 (TODO: needs zsig gen)
# NOT for glibc ARM32 (Intellian, Cobham E710) — glibc-arm32.r2 (TODO: needs debian/armhf zsigs)

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo musl/armv7/musl-libc.zsig
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
