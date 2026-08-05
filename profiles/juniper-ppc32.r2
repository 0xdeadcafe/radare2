# Juniper JunOS PPC32 Big-Endian — family f5e1d8fb
# Platform: Juniper SRX/J-Series with PowerPC CPU (older hardware gen)
# Architecture: PPC32 BE, FreeBSD userland
#
# Binaries: kmd, dhcpd, HTTPD-GK, openflowd, JDHCPD, libssl.so
# Symbols:  symbols/juniper/family_f5e1d8fb/
#
# Usage: r2 -i profiles/juniper-ppc32.r2 kmd
#
# NOTE: juniper-srx.r2 is for MIPS64 JunOS binaries (family c8711279 and newer).
#       This profile is for the PPC32 family f5e1d8fb.

e asm.arch=ppc
e asm.bits=32
e cfg.bigendian=true

e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e bin.demangle=true

# Zignature matching thresholds
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# Type definitions
e dir.types=/root/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h
to juniper/srx_httpd_gk.h

e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

?e [juniper-ppc32] Juniper JunOS PPC32 family f5e1d8fb profile loaded.
?e [juniper-ppc32]   Load symbols: . /root/.local/share/radare2/symbols/juniper/family_f5e1d8fb/kmd.r2
