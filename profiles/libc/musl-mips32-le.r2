# libc/musl-mips32-le.r2 — musl libc MIPS32 Little-Endian (OpenWrt ramips/mt7621)
#
# Targets:
#   OpenWrt ramips/mt7621 (MediaTek MT7621, MIPSEL 32-bit, musl libc)
#   OpenWrt bcm47xx (Broadcom BCM4xxx MIPSEL, musl libc post-CC era)
#
# Source: zigns/openwrt/mipsel_24kc/musl-libc.zsig

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo openwrt/mipsel_24kc/musl-libc.zsig
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
