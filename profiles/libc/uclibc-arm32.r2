# libc/uclibc-arm32.r2 — uClibc-ng ARM32 (armv5-eabi soft-float)
#
# Targets:
#   Supermicro BMC ARM926EJ-S (ARMv5TE, uClibc-ng)
#   Embedded appliances using Buildroot + uClibc arm cross-toolchain
#   Any ARM32 binary with interpreter: /lib/ld-uClibc.so.0
#
# Source: zigns/uclibc/arm32/uclibc-libc.zsig (Bootlin armv5-eabi 2024.02)
# Coverage: 3269 signatures (76% named — libc, libm, libpthread, librt)

e zign.mincc=1
e zign.minsz=4

zo uclibc/arm32/uclibc-libc.zsig
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl-arm32.h
to libc/errno.h
to libc/signal.h
