# supermicro-bmc-arm.r2 — Supermicro BMC ARM32 Analysis Profile
#
# Target: Supermicro MBAST2500 and related BMC firmware
#   SoC:  ARM926EJ-S (ARMv5TEJ, no Thumb in CGI binaries)
#   FS:   cramfs (extracted by binwalk / firmware-unpacker skill)
#   HTTP: lighttpd CGI interface (ipmi.cgi, url_redirect.cgi, sys_mgmt.cgi)
#   Pkgs: BusyBox, OpenIPMI partial stack, proprietary IPMI message router
#
# Selected automatically when:
#   vendor slug = "supermicro"  AND  arch = arm  AND  bits = 32
# See: scripts/aether_r2profile.py _VENDOR_PROFILE_MAP ("arm","32","supermicro")
#
# Usage: r2 -i profiles/supermicro-bmc-arm.r2 ipmi.cgi
#        Or from r2: . profiles/supermicro-bmc-arm.r2

# ── Architecture: ARM32 LE, ARMv5 (no Thumb in CGI binaries) ─────────────────
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false
e asm.cpu=arm926ej-s
# Disable Thumb auto-detection — ARM926EJ-S CGI binaries are pure ARM mode.
# If analysing a binary that DOES use Thumb (e.g. a busybox applet), override:
#   e asm.bits=16 ; e asm.thumb=true
e asm.thumb=false

# ── Analysis tuning ───────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true          ; # tag dispatch tables (ipmi.cgi has 58-entry table)
e anal.strings=true
e anal.datarefs=true
e anal.jmp.indir=true        ; # indirect branches through function pointer arrays

# ── Zignature settings ────────────────────────────────────────────────────────
e zign.graph=true
e zign.refs=true
# Lower matching thresholds — default mincc=10 kills simple functions
e zign.mincc=1
e zign.minsz=4

# ── Visual ────────────────────────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# ── Type definitions ──────────────────────────────────────────────────────────
# Standard libc types for cleaner decompilation
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl-arm32.h
to libc/errno.h
to libc/signal.h

# Supermicro BMC / IPMI types (ipmi.cgi tag dispatch table, CGI env structs,
# IPMI session, libweb session IP bypass, cgiGetPostVariable)
# Path after install.sh: ~/.local/share/radare2/types/supermicro/
to supermicro/bmc_structs.h

# ── Zignatures ──────────────────────────────────────────────────────────────
# uClibc-ng ARM32 (Bootlin armv5-eabi 2024.02 — ARM926EJ-S compatible)
# 3269 sigs, 76% named: libc, libm, libpthread, librt
zo uclibc/arm32/uclibc-libc.zsig

# ── Magic scans ───────────────────────────────────────────────────────────────
/m /root/.local/share/radare2/magic/crypto_tables.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic

# ── Attack surface orientation ────────────────────────────────────────────────
# ipmi.cgi attack surface summary (from 2026-04-24 session):
#
#   Entry point:   main() → parse QUERY_STRING → tag_dispatch()
#   Dispatch:      58-entry table at .data+0x??? — each entry has:
#                    { char *tag_name, handler_fn*, uint8_t auth_required }
#                  auth_required=0 on sensitive tags = pre-auth handler call
#   Sink:          sprintf/snprintf/strcpy in per-tag handlers — stack overflow
#   Surface:       HTTP GET /cgi-bin/ipmi.cgi?tag=<TAG>&<params>
#
#   url_redirect.cgi:
#     Entry:       main() → getenv("QUERY_STRING") → sscanf into fixed buffer
#     Sink:        sscanf(qs, "url=%s", fixed_buf[256]) → stack overflow
#     Surface:     HTTP GET /cgi-bin/url_redirect.cgi?url=<PAYLOAD> (pre-auth)
#
# Pattern reference: vault/Patterns/CGI_Tag_Dispatch_Auth_Bypass.md
#
# Suggested first r2 commands after loading:
#   aa ; afl~tag_dispatch,handler,cgi   # find dispatch and handler functions
#   iz~QUERY_STRING,tag,url             # locate string refs to CGI env vars
#   /c sprintf,strcpy,sscanf            # quick sink scan

echo "Supermicro BMC ARM32 profile loaded."
echo "Key structs: tag_dispatch_entry {char* name, void* handler, uint8_t auth_required}"
echo "Reference: vault/Patterns/CGI_Tag_Dispatch_Auth_Bypass.md"
