# Linux x86 (32-bit) with glibc Analysis Profile
# For standard Debian/Ubuntu i386 userland and older 32-bit Linux firmware.
# Typical targets: NAS daemons, x86 router firmware, CGI binaries, CTF i386.
#
# Loads: glibc libc6 + 21 libraries (debian/i386, Ubuntu 22.04)
#        Full POSIX type definitions + OpenSSL + zlib types
#
# Usage: r2 -i profiles/linux-glibc-x86.r2 binary
#        Or from r2: . profiles/linux-glibc-x86.r2

# ── Architecture settings ────────────────────────────────────────────────────
e asm.arch=x86
e asm.bits=32
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

# ── Load glibc / library signatures ─────────────────────────────────────────
# zo uses dir.zigns as base (set by install.sh / .radare2rc.local)
# Populated by: python3 tool/generate-debian-libs-zsig.py --arch i386
zo debian/i386/libc6.zsig
zo debian/i386/libgcc.zsig
zo debian/i386/libstdc++.zsig
zo debian/i386/libssl.zsig
zo debian/i386/libcrypto-static.zsig
zo debian/i386/zlib.zsig
zo debian/i386/libbz2.zsig
zo debian/i386/liblzma.zsig
zo debian/i386/libbrotli.zsig
zo debian/i386/libcurl.zsig
# libmbedtls-dev not packaged for i386 in Ubuntu 22.04 — skipped
zo debian/i386/libevent.zsig
zo debian/i386/libgnutls.zsig
zo debian/i386/libprotobuf.zsig
zo debian/i386/libsodium.zsig
zo debian/i386/libsqlite3.zsig
zo debian/i386/libxml2.zsig
zo debian/i386/libzstd.zsig
zo debian/i386/liblz4.zsig
zo debian/i386/libsnappy.zsig
zo debian/i386/libpcre2.zsig
zo debian/i386/libavformat.zsig
zo debian/i386/libavutil.zsig

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
