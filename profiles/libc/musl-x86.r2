# libc/musl-x86.r2 — musl libc x86 32-bit
#
# Targets:
#   Alpine Linux i386 userland binaries
#   Any x86 32-bit binary with intrp: /lib/ld-musl-i386.so.1
#   Rare embedded targets (x86 industrial firmware) built with musl
#
# Source: zigns/musl/x86/musl-libc.zsig
# Coverage: ~14,000 function signatures (musl 1.2.x full libc)
#
# NOT for glibc x86 — use a debian/i386 zsig set instead
# NOT for musl x86_64 — use musl-x64.r2

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo musl/x86/musl-libc.zsig
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
