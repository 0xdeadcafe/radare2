# libc/musl-mips32-be.r2 — musl libc MIPS32 Big-Endian (OpenWrt ath79/mips32r2)
#
# Targets:
#   OpenWrt ath79/generic (AR7xxx/AR9xxx, MIPS32r2 BE, musl libc)
#   OpenWrt mips_24kc target (most Atheros-based routers post-Chaos Calmer)
#   Any firmware built with OpenWrt SDK mips_24kc toolchain
#
# Source: zigns/openwrt/mips_24kc/musl-libc.zsig
# Coverage: ~15,600 function signatures (full musl 1.2.x libc)
#
# NOT for uClibc targets (DJI, pre-OpenWrt-15 routers) — use uclibc-mips32.r2

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo openwrt/mips_24kc/musl-libc.zsig
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
