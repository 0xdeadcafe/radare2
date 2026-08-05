# FreeBSD x86-64 Analysis Profile
# For FreeBSD-based binaries: JunOS daemons, pfSense, OPNsense, TrueNAS.
#
# FreeBSD uses glibc-compatible libc but with different syscall numbers and
# BSD-specific extensions (kqueue, Capsicum, jails). The debian/amd64 libc6
# zsig provides reasonable coverage for shared function implementations.
#
# Usage: r2 -i profiles/freebsd-x64.r2 binary
#        Or from r2: . profiles/freebsd-x64.r2
#
# Identify FreeBSD binary: `iI~OS` shows "freebsd"; elf interpreter is
# /libexec/ld-elf.so.1 rather than /lib64/ld-linux-x86-64.so.2

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
e zign.mincc=1
e zign.minsz=4

# ── Load type definitions ────────────────────────────────────────────────────
# FreeBSD userland is largely POSIX-compatible; libc types apply.
# freebsd.h adds BSD-specific extensions (kqueue, Capsicum, jail, BSD stat).
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
to freebsd/freebsd.h
to openssl/ssl.h
to openssl/crypto.h
to zlib/zlib.h

# ── Load signatures ──────────────────────────────────────────────────────────
# debian/amd64 libc6 is glibc but function bodies are similar enough for
# cross-OS matching of standard library functions (memcpy, strcmp, printf, etc.)
# Match rate ~60-70% on FreeBSD binaries for standard functions.
zo debian/amd64/libc6.zsig
zo debian/amd64/libssl.zsig
zo debian/amd64/zlib.zsig
zo debian/amd64/libcurl.zsig

# ── Visual settings ──────────────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
e asm.var=true

# ── Post-load notes ──────────────────────────────────────────────────────────
# Juniper JunOS specifics:
#   - Use profiles/juniper-srx.r2 for JunOS MIPS64 SRX binaries
#   - Use profiles/juniper-ppc32.r2 for JunOS PPC32 family_f5e1d8fb
#   - Use profiles/freebsd-x64.r2 for general FreeBSD x64 userland
#
# After this profile loads:
#   aa         - full analysis
#   z/         - apply loaded zsigs
#   axt sym.imp.kqueue   - find all kqueue-based event loops
#   axt sym.imp.cap_enter - find Capsicum sandbox entry points
