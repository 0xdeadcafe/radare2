# libc/glibc-arm32.r2 — GNU libc ARM32 (armhf, little-endian)
#
# Targets:
#   Intellian iARM firmware (ARM32 LE, glibc, /lib/ld-linux.so.3)
#   Cobham / Viasat ARM32 userland
#   Furuno FELCOM ARM32 userland
#   Any ARM32 binary with intrp: /lib/ld-linux-armhf.so.3 or /lib/ld-linux.so.3
#
# Source: zigns/glibc/armhf/glibc-libc.zsig
# Notes:
#   - glibc-specific; do NOT use for musl or uClibc targets
#   - loaded automatically by aether_r2profile.py when ELF interpreter indicates glibc

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo glibc/armhf/glibc-libc.zsig
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl-arm32.h
to libc/errno.h
to libc/signal.h
