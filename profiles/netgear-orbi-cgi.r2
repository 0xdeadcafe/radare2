# NETGEAR Orbi net-cgi Analysis Profile
# Target:  NETGEAR Orbi RBR50 router — net-cgi CGI binary (HTTP handler)
# CPU:     ARM Cortex-A (ARM32 Thumb LE)
# OS:      Linux (musl libc, busybox-based OpenWrt derivative)
# Format:  PIE shared object (.so) — r2 loads at 0x0; angr maps at 0x400000
#
# Confirmed from finding: 29bc3697 (Orbi RBR50 V2.7.5.4)
# Status: POC_FOUND
#
# IMPORTANT: PIE base address
#   r2 loads PIE .so at virtual address 0x0 by default.
#   angr / Modality maps at 0x400000.
#   For Modality PoC development: use -B 0x400000 to align addresses.
#   Example:
#     r2 -B 0x400000 -i profiles/netgear-orbi-cgi.r2 net-cgi
#
# Usage:
#   r2 -i profiles/netgear-orbi-cgi.r2 net-cgi          # r2 session (addr = 0x0-based)
#   r2 -B 0x400000 -i profiles/netgear-orbi-cgi.r2 net-cgi  # Modality-aligned addresses

# =============================================================================
# Architecture
# =============================================================================
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# Thumb PIE — enable Thumb mode and indirect branch resolution
ahb 16
e bin.plt.resolve=true
e anal.jmp.indir=true

# =============================================================================
# Analysis settings
# =============================================================================
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e anal.datarefs=true
e bin.demangle=true

# =============================================================================
# Zignatures (musl ARM32 — net-cgi uses musl libc)
# =============================================================================
e zign.graph=true
e zign.refs=true
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4
zo musl/armhf/musl-libc.zsig

# =============================================================================
# Type definitions
# =============================================================================
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h

# =============================================================================
# Attack surface notes
#
# net-cgi handles HTTP CGI requests for the Orbi web interface.
# Key sinks (search after aa + z/):
#   system()    — command injection via unsanitised CGI parameters
#   popen()     — command injection
#   sprintf()   — stack-based buffer overflow in URL/param processing
#   strcpy()    — unbounded copy from request parameters
#
# Entry point pattern:
#   1. CGI reads QUERY_STRING / POST body via getenv / fgets
#   2. Parses key=value pairs into internal struct
#   3. Dispatches to handler by URL path
#   4. Handler passes values to system() / popen() without sanitisation
#
# Find CGI dispatch:
#   / QUERY_STRING      — locate getenv call site
#   axt @ hit0_0        — trace to parser function
#   iz~system           — find "system" string references
#   axt @ sym.imp.system — find all callers after z/
# =============================================================================

# =============================================================================
# Modality alignment note
#
# angr_base = 0x400000
# When Modality reports a crash address like 0x4XXXXX, subtract 0x400000
# to get the file-offset / r2 address (when loaded without -B).
# =============================================================================

# =============================================================================
# Crypto/protocol scan
# =============================================================================
/m /root/.local/share/radare2/magic/crypto_tables.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic

# =============================================================================
# Display
# =============================================================================
e asm.describe=true
e asm.comments=true
e asm.cmt.col=55
e asm.xrefs=true

?e [netgear-orbi-cgi] ARM32 Thumb PIE profile loaded.
?e [netgear-orbi-cgi] r2 base = 0x0  |  angr/Modality base = 0x400000
?e [netgear-orbi-cgi] Use -B 0x400000 to align addresses for Modality.
