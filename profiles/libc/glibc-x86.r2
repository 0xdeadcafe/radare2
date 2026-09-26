# libc/glibc-x86.r2 — GNU libc x86 32-bit (i386/i686)
#
# Targets:
#   Older NAS / router firmware (i686 Linux, glibc)
#   CTF i386 binaries
#   x86 32-bit server daemons
#   Any x86/32 ELF with intrp: /lib/ld-linux.so.2
#
# Source: zigns/debian/i386/ (Ubuntu 22.04 jammy)
# Generate: python3 tool/generate-debian-libs-zsig.py --arch i386

e zign.mincc=1
e zign.minsz=4

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
zo debian/i386/libevent.zsig
zo debian/i386/libgnutls.zsig
# libmbedtls-dev not packaged for i386 in Ubuntu 22.04
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

e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
to openssl/ssl.h
to openssl/crypto.h
to zlib/zlib.h
