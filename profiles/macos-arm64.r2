# macOS ARM64 (Apple Silicon) Analysis Profile
# For Mach-O binaries on Apple Silicon (M1/M2/M3/M4) — macOS 12.x+ (Monterey+).
# Also useful for iOS arm64 binaries (compatible subset of Mach-O ABI).
#
# Usage: r2 -i profiles/macos-arm64.r2 binary
#        Or from r2: . profiles/macos-arm64.r2
#
# Identify: `iI~os` shows "macos"; `iI~arch` shows "arm" or "arm64"
# Apple uses the AArch64 ABI with Apple-specific PAC (Pointer Authentication).

# ── Architecture settings ────────────────────────────────────────────────────
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

# ── Mach-O / Apple AArch64 specific ─────────────────────────────────────────
e bin.lang=objc
e bin.demangle=true
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e anal.trycatch=true

# ── PLT resolution for Mach-O stubs ─────────────────────────────────────────
# macOS uses __stubs section instead of PLT; r2 resolves most automatically.
e bin.plt.resolve=true

# ── Zignature quality flags ──────────────────────────────────────────────────
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# ── Load type definitions ────────────────────────────────────────────────────
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
to freebsd/freebsd.h

# ── Signatures ───────────────────────────────────────────────────────────────
# No native macOS zsigs yet (requires macOS SDK or Apple host).
# Third-party libs compiled from identical source -- high cross-OS match rate.
# Intentionally excluded: libstdc++ (macOS uses libc++ ABI).
# TODO: replace with native macOS zsigs when macOS SDK becomes available.
zo debian/arm64/libc6.zsig
zo debian/arm64/libgcc.zsig
zo debian/arm64/libssl.zsig
zo debian/arm64/libcrypto-static.zsig
zo debian/arm64/zlib.zsig
zo debian/arm64/libbz2.zsig
zo debian/arm64/liblzma.zsig
zo debian/arm64/libbrotli.zsig
zo debian/arm64/libmbedtls.zsig
zo debian/arm64/libcurl.zsig
zo debian/arm64/libevent.zsig
zo debian/arm64/libgnutls.zsig
zo debian/arm64/libprotobuf.zsig
zo debian/arm64/libsodium.zsig
zo debian/arm64/libsqlite3.zsig
zo debian/arm64/libxml2.zsig
zo debian/arm64/libzstd.zsig
zo debian/arm64/liblz4.zsig
zo debian/arm64/libsnappy.zsig
zo debian/arm64/libpcre2.zsig
zo debian/arm64/libavformat.zsig
zo debian/arm64/libavutil.zsig

# ── Visual settings ──────────────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.var=true

# ── Post-load notes ──────────────────────────────────────────────────────────
# Apple Silicon AArch64 specifics:
#   - PAC (Pointer Authentication) instructions: PACIA, PACIB, AUTIA, AUTIB
#     r2 6.x decodes these correctly with asm.arch=arm + bits=64
#   - BTI (Branch Target Identification): look for HINT #34/#36 (BTI c/j/jc)
#   - Rosetta 2 translation layer may be present in some binaries
#   - Universal/fat binaries: use 'r2 -a arm' or rabin2 -x to extract arm64
#
#   iS              - list Mach-O segments
#   iz              - strings (ObjC selectors, Swift method names)
#   axt sym.imp.objc_msgSend   - ObjC dispatch
#   /c _dispatch_async - GCD (Grand Central Dispatch) async blocks
#   /c xpc_connection_create   - XPC inter-process communication
