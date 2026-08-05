# libc/glibc-arm64.r2 — GNU libc (glibc) AArch64
#
# Targets:
#   HPE iLO 7 restserver (AArch64 PIE, glibc, Debian-based)
#   Any AArch64 binary with intrp: /lib/ld-linux-aarch64.so.1
#   Debian/Ubuntu ARM64 userland binaries
#
# Source: zigns/debian/arm64/*.zsig
# Coverage: libc6 (full glibc), libgcc, libssl, libcurl, libmbedtls,
#           zlib, libbrotli, libbz2, liblzma, libgnutls, libevent
#
# Load order: libc6 first (most matches), then optional libs.
# These are glibc-specific — do NOT use for musl (false positives on format funcs).
#
# NOT for musl ARM64 (Alpine) — use musl-arm64.r2
# NOT for Android ARM64 (Bionic) — use bionic-arm64.r2
# For ARM32 glibc targets, use profiles/libc/glibc-arm32.r2.

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

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
