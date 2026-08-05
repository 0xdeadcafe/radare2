# libc/uclibc-mips32.r2 — uClibc MIPS32 (Big-Endian or Little-Endian)
#
# Targets:
#   DJI Wi-Fi module (clisrv, MIPS32 BE, uClibc-ng 0.9.33)
#   Cobham BGAN Explorer 500/300 (eCos flat, MIPS32 BE — load manually)
#   Generic OpenWrt Barrier Breaker era firmware (uClibc 0.9.33.x)
#
# Source: skel/.local/share/radare2/zigns/uclibc/mips32/uclibc-libc.zsig
# Generated from: uClibc-ng 0.9.33 compiled for mips32-unknown-linux-uclibc
#
# Coverage: ~3,400 function signatures (libc, libm, libpthread, libdl)
# Correct lib: ALWAYS use this for uClibc targets. Do NOT use musl-libc.zsig —
# false positives occur because musl and uClibc share many short functions
# but have different implementations for string/memory/format functions.
#
# Usage (sourced by a full profile — not invoked directly):
#   . profiles/libc/uclibc-mips32.r2

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo uclibc/mips32/uclibc-libc.zsig
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
