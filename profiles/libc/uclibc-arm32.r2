# libc/uclibc-arm32.r2 — uClibc ARM32 (ARM926EJ-S and similar)
#
# Targets:
#   Supermicro BMC (ARM926EJ-S, uClibc 0.9.33, /lib/libuClibc-0.9.33.so)
#   Any ARM32 binary with interpreter /lib/ld-uClibc.so.0
#
# STATUS: STUB — zsig not yet generated.
# See profiles/libc/TODO.md for generation instructions.

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4
#
# To generate the required zsig:
#   # Build uClibc-ng for arm-linux-uclibc or extract from Supermicro firmware:
#   #   find rootfs/ -name "libuClibc*.so" | head -1 → extract .so
#   # Then:
#   rasign2 -A -o zigns/uclibc/arm32/uclibc-libc.zsig /path/to/libuClibc.so
#   mkdir -p zigns/uclibc/arm32/
#   # Uncomment the zo line below once the zsig exists.

# zo uclibc/arm32/uclibc-libc.zsig
# to libc/functions.h
# to libc/socket.h
# to libc/fcntl.h
# to libc/errno.h
# to libc/signal.h
