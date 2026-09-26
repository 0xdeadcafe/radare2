# macOS x86-64 (Intel) Analysis Profile
# For Mach-O binaries on Intel macOS 10.15–13.x (Catalina through Ventura).
# Also useful for macOS Mach-O dylibs and frameworks.
#
# Usage: r2 -i profiles/macos-x64.r2 binary
#        Or from r2: . profiles/macos-x64.r2
#
# Identify: `iI~os` shows "macos"; `iI~type` shows "DYLIB" or "EXECUTE"
# macOS Mach-O uses a different object format — r2 parses it natively.

# ── Architecture settings ────────────────────────────────────────────────────
e asm.arch=x86
e asm.bits=64
e cfg.bigendian=false

# ── Mach-O specific settings ─────────────────────────────────────────────────
# bin.lang: helps with ObjC/Swift demangle
e bin.lang=objc
e bin.demangle=true
# macOS PIE + ASLR — always PIE
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e anal.trycatch=true

# ── Zignature quality flags ──────────────────────────────────────────────────
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# ── Load type definitions ────────────────────────────────────────────────────
# macOS uses a BSD-derived libc (libSystem.dylib wrapping libc.dylib).
# POSIX types apply; BSD extensions (kqueue, kevent) are present.
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
to freebsd/freebsd.h

# ── Signatures ───────────────────────────────────────────────────────────────
# Native macOS zsigs (compiled from Apple open source + SDK)
zo macos/x86_64/libSystem.zsig
zo macos/x86_64/libm.zsig
# Third-party libs (statically linked OpenSSL, zlib, etc.)
# compiled from identical source — high cross-OS match rate:
zo debian/amd64/libc6.zsig
zo debian/amd64/libgcc.zsig
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

# ── Visual settings ──────────────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.var=true

# ── Post-load notes ──────────────────────────────────────────────────────────
# macOS-specific analysis tips:
#   ii~dylib_stub   - list Mach-O stubs (imported functions)
#   iS              - list Mach-O segments (__TEXT, __DATA, __OBJC, etc.)
#   iz              - strings (includes ObjC selector strings)
#   axt sym.imp.objc_msgSend   - find all ObjC message sends
#   /c dlopen       - find dynamic loading
#   /c NSURLSession - find URL networking calls
#
# For Swift binaries:
#   e bin.lang=swift
#   aa; afl~swift   - list Swift functions
