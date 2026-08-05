# Linux x86-64 with glibc Analysis Profile
# For standard Debian/Ubuntu/RHEL x86-64 userland binaries.
# Also suitable for: server daemons, CTF binaries, security tools.
#
# Loads: glibc libc6 + libssl + libcurl + ffmpeg + zlib zsigs (13 libraries)
#        Full POSIX type definitions + OpenSSL + zlib + FFmpeg types
#
# Usage: r2 -i profiles/linux-glibc-x64.r2 binary
#        Or from r2: . profiles/linux-glibc-x64.r2

# ── Architecture settings ────────────────────────────────────────────────────
e asm.arch=x86
e asm.bits=64
e cfg.bigendian=false

# ── PLT/GOT resolution ───────────────────────────────────────────────────────
e bin.plt.resolve=true

# ── Analysis settings ────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true
e anal.trycatch=true

# ── Zignature quality flags ──────────────────────────────────────────────────
e zign.graph=true
e zign.refs=true
# Default mincc=10 silently kills single-BB glibc wrappers (syscall stubs)
e zign.mincc=1
e zign.minsz=4

# ── Load glibc type definitions ──────────────────────────────────────────────
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
to openssl/ssl.h
to openssl/crypto.h
to zlib/zlib.h
to ffmpeg/avformat.h
to ffmpeg/avutil.h
to ffmpeg/avcodec.h

# ── Load glibc / library signatures ─────────────────────────────────────────
# zo uses dir.zigns as base (set by install.sh / .radare2rc.local)
zo debian/amd64/libc6.zsig
zo debian/amd64/libgcc.zsig
zo debian/amd64/libssl.zsig
zo debian/amd64/zlib.zsig
zo debian/amd64/libbz2.zsig
zo debian/amd64/liblzma.zsig
zo debian/amd64/libbrotli.zsig
zo debian/amd64/libmbedtls.zsig
zo debian/amd64/libcurl.zsig
zo debian/amd64/libevent.zsig
zo debian/amd64/libgnutls.zsig
zo debian/amd64/libavformat.zsig
zo debian/amd64/libavutil.zsig

# ── Visual settings ──────────────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.var=true

# ── Post-load notes ──────────────────────────────────────────────────────────
# After this profile loads:
#   aa         - full analysis
#   z/         - apply loaded zsigs
#   aaft       - propagate type info to matched functions
#   . ~/.local/share/radare2/scripts/elf-sinks.r2   - label dangerous sinks
