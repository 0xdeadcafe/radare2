# libc/musl-x64.r2 — musl libc x86-64
#
# Targets:
#   Alpine Linux x86-64 userland binaries
#   Any x86-64 binary with intrp: /lib/ld-musl-x86_64.so.1
#   Statically linked musl x86-64 binaries (e.g. busybox-static)
#
# Source: zigns/musl/x86_64/musl-libc.zsig
# Coverage: ~15,600 function signatures (musl 1.2.x full libc)
#
# NOT for glibc x86-64 — use glibc-x64.r2

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo musl/x86_64/musl-libc.zsig
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
