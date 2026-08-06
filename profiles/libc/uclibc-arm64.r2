# libc/uclibc-arm64.r2 — uClibc-ng AArch64
#
# Targets:
#   OpenWrt AArch64 targets using uClibc-ng (older builds pre-musl migration)
#   Rockchip RK35xx, Amlogic S905X, RPi 4/5 OpenWrt builds with uclibc
#   Any AArch64 binary with intrp: /lib/ld-uClibc.so.0 or /lib/ld-uClibc-1.0.xx.so
#
# Source: zigns/uclibc/arm64/uclibc-libc.zsig
#         Bootlin aarch64--uclibc--stable-2024.02-1, named objects only
# Coverage: 1961 named uClibc C API functions (malloc, printf, open, sigwait, etc.)

e zign.mincc=1
e zign.minsz=4

zo uclibc/arm64/uclibc-libc.zsig
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
