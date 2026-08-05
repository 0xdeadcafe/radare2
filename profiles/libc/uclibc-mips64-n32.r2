# libc/uclibc-mips64-n32.r2 — uClibc MIPS64 Big-Endian, N32 ABI (Cavium Octeon+)
#
# Targets:
#   Juniper JunOS MIPS64 daemons compiled with N32 ABI
#   Cavium Octeon+ firmware using the N32 hybrid ABI (32-bit pointers, 64-bit registers)
#
# Source: zigns/uclibc/mips64-n32/uclibc-libc.zsig
# Coverage: ~2,800 function signatures (libc, libm, libpthread)
#
# NOT for N64 ABI — use uclibc-mips64.r2
# NOT for MIPS32 BE uClibc — use uclibc-mips32.r2

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo uclibc/mips64-n32/uclibc-libc.zsig
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
