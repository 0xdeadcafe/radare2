# libc/glibc-x64.r2 — GNU libc (glibc) x86-64
#
# Targets:
#   Debian/Ubuntu x86-64 userland binaries
#   Any x86-64 binary with intrp: /lib64/ld-linux-x86-64.so.2
#
# Source: zigns/debian/amd64/*.zsig

# Zignature matching thresholds (default mincc=10 kills syscall wrappers)
e zign.mincc=1
e zign.minsz=4

zo debian/amd64/libc6.zsig
zo debian/amd64/libgcc.zsig
zo debian/amd64/libstdc++.zsig
zo debian/amd64/libssl.zsig
zo debian/amd64/libcrypto-static.zsig
zo debian/amd64/zlib.zsig
zo debian/amd64/libbz2.zsig
zo debian/amd64/liblzma.zsig
zo debian/amd64/libbrotli.zsig
zo debian/amd64/libmbedtls.zsig
zo debian/amd64/libcurl.zsig
zo debian/amd64/libevent.zsig
zo debian/amd64/libgnutls.zsig
zo debian/amd64/libprotobuf.zsig
zo debian/amd64/libsodium.zsig
zo debian/amd64/libsqlite3.zsig
zo debian/amd64/libxml2.zsig
zo debian/amd64/libzstd.zsig
zo debian/amd64/liblz4.zsig
zo debian/amd64/libsnappy.zsig
zo debian/amd64/libpcre2.zsig
zo debian/amd64/libavformat.zsig
zo debian/amd64/libavutil.zsig
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
