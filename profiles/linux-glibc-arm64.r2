# Linux aarch64 with glibc Analysis Profile
# For standard Debian/Ubuntu ARM64 userland binaries (Raspberry Pi OS 64-bit,
# HPE iLO 7, server ARM64, AWS Graviton workloads, etc.)
#
# Loads: glibc libc6 + libssl + libcurl + ffmpeg + zlib zsigs (13 libraries)
#        Full POSIX type definitions + OpenSSL + zlib + FFmpeg types
#
# Usage: r2 -i profiles/linux-glibc-arm64.r2 binary
#        Or from r2: . profiles/linux-glibc-arm64.r2
#
# NOT for musl ARM64 (Alpine) — use linux-musl-arm64.r2
# NOT for Android ARM64 (Bionic) — use android-arm64.r2

# ── Architecture settings ────────────────────────────────────────────────────
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

# ── PLT→GOT resolution for AArch64 PIE ──────────────────────────────────────
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
zo debian/arm64/libc6.zsig
zo debian/arm64/libgcc.zsig
zo debian/arm64/libssl.zsig
zo debian/arm64/zlib.zsig
zo debian/arm64/libbz2.zsig
zo debian/arm64/liblzma.zsig
zo debian/arm64/libbrotli.zsig
zo debian/arm64/libmbedtls.zsig
zo debian/arm64/libcurl.zsig
zo debian/arm64/libevent.zsig
zo debian/arm64/libgnutls.zsig
zo debian/arm64/libavformat.zsig
zo debian/arm64/libavutil.zsig

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
