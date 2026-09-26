# Linux ARM32 with glibc Analysis Profile
# For ARM32 Cortex-A binaries using glibc (Android NDK cross-compiled tools,
# older embedded Linux distributions, Raspberry Pi OS 32-bit).
#
# Usage: r2 -i profiles/linux-glibc-arm32.r2 binary
#        Or from r2: . profiles/linux-glibc-arm32.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# PLT→GOT resolution for ARM32 PIE
e bin.plt.resolve=true

# Analysis settings
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true

# Zignature settings
e zign.graph=true
e zign.refs=true
# Lower matching thresholds — default mincc=10 kills simple syscall wrappers (1 BB)
e zign.mincc=1
e zign.minsz=4

# Load glibc type definitions
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl-arm32.h
to libc/errno.h
to libc/signal.h
to openssl/ssl.h
to openssl/crypto.h
to zlib/zlib.h

# Load glibc ARM32 (armhf) signatures — full debian/armhf set
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

# Visual settings
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# After loading, run analysis:
#   aa      - Full analysis
#   z/      - Apply signatures to functions
