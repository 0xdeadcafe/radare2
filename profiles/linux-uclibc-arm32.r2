# Linux ARM32 with uClibc-ng Analysis Profile
# For ARMv5TE / Cortex-A binaries using uClibc (Supermicro BMC, old embedded Linux).
#
# Identifies: /lib/ld-uClibc.so.0 or /lib/ld-uclibc.so.0 as ELF interpreter.
# SoC:  ARM926EJ-S class (ARMv5TE) -- no Thumb in most uClibc CGI binaries.
# Also covers armv7-eabihf uClibc targets (newer embedded Linux with hard-float).
#
# Usage: r2 -i profiles/linux-uclibc-arm32.r2 binary
#        Or from r2: . profiles/linux-uclibc-arm32.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# PLT/GOT resolution for ARM32 PIE
e bin.plt.resolve=true

# Analysis settings
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true

# Zignature settings
e zign.graph=true
e zign.refs=true
# Default mincc=10 kills single-BB uClibc wrappers (syscall stubs)
e zign.mincc=1
e zign.minsz=4

# Load uClibc + POSIX type definitions
# fcntl-arm32.h: ARM32-correct struct stat (120 bytes, 64-bit dev/ino via long long)
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl-arm32.h
to libc/errno.h
to libc/signal.h

# Load uClibc-ng ARM32 signatures (Bootlin armv5-eabi 2024.02)
# 3269 sigs, 76% named: libc, libm, libpthread, librt
zo uclibc/arm32/uclibc-libc.zsig

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# Post-load notes:
#   aa      -- full analysis
#   z/      -- apply uClibc signatures
#   aaft    -- propagate type info
#   . ~/.local/share/radare2/scripts/elf-sinks.r2  -- label dangerous sinks
