# libc/glibc-arm32.r2 — GNU libc ARM32 (armhf, little-endian)
#
# Targets:
#   Intellian iARM firmware (ARM32 LE, glibc, /lib/ld-linux.so.3)
#   Cobham / Viasat ARM32 userland
#   Furuno FELCOM ARM32 userland
#   Any ARM32 binary with intrp: /lib/ld-linux-armhf.so.3 or /lib/ld-linux.so.3
#
# Source: zigns/debian/armhf/ (Ubuntu 22.04 jammy-security)
# Notes:
#   - glibc-specific; do NOT use for musl or uClibc targets
#   - loaded automatically by aether_r2profile.py when ELF interpreter indicates glibc

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo debian/armhf/libc6.zsig
zo debian/armhf/libgcc.zsig
zo debian/armhf/libstdc++.zsig
zo debian/armhf/libssl.zsig
zo debian/armhf/libcrypto-static.zsig
zo debian/armhf/zlib.zsig
zo debian/armhf/libbz2.zsig
zo debian/armhf/liblzma.zsig
zo debian/armhf/libbrotli.zsig
zo debian/armhf/libmbedtls.zsig
zo debian/armhf/libcurl.zsig
zo debian/armhf/libevent.zsig
zo debian/armhf/libgnutls.zsig
zo debian/armhf/libprotobuf.zsig
zo debian/armhf/libsodium.zsig
zo debian/armhf/libsqlite3.zsig
zo debian/armhf/libxml2.zsig
zo debian/armhf/libzstd.zsig
zo debian/armhf/liblz4.zsig
zo debian/armhf/libsnappy.zsig
zo debian/armhf/libpcre2.zsig
zo debian/armhf/libavformat.zsig
zo debian/armhf/libavutil.zsig

e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl-arm32.h
to libc/errno.h
to libc/signal.h
to openssl/ssl.h
to openssl/crypto.h
to zlib/zlib.h
