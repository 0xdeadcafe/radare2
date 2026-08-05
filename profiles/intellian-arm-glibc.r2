# r2 profile: Intellian iARM-GX / iARM-nx (ARM32 LE, glibc, Linux)
#
# Targets:
#   Intellian iARM-GX  — v1.05, v1.14, v2.07 (Viasat/Intellian GX VSAT)
#   Intellian iARM-nx  — v2.02–v2.07 (JRC JUE-100GX / iDirect NX VSAT)
#
# SoC:    ARM Cortex-A5 / A7 (ARMv7-A LE, Thumb-2 support in CGI/daemon ELFs)
# OS:     Embedded Linux + glibc
# HTTP:   lighttpd CGI interface — ports 80 (redirect) / 443 (HTTPS)
#         Key CGI binaries: nxagent.cgi, setagent.cgi, web_svc.cgi
# Daemons: acu_server (TCP:4002 UIF plaintext, TCP:94002 UIF+stunnel)
#          smux (multiplexer), bim_agent, cam_server
# Shared:  libcommon.so — escape_expand(), make_acu_auth_command(), check_login_id_passwd()
#
# Selected automatically when:
#   vendor slug = "intellian"  AND  arch = arm  AND  bits = 32
# See: scripts/aether_r2profile.py _VENDOR_PROFILE_MAP ("arm","32","intellian")
#
# Usage:
#   r2 -i profiles/intellian-arm-glibc.r2 nxagent.cgi
#   Or from within r2: . profiles/intellian-arm-glibc.r2

# ── Architecture: ARM32 LE, ARMv7 Thumb-2 ────────────────────────────────────
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false
e asm.cpu=cortex-a7
e anal.cc=arm             ; # ARM EABI5 calling convention

# ── Analysis tuning ───────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true       ; # JSON command dispatch table (~60 COMMAND handler entries
                           ;   in nxagent.cgi); SBUS/UIF dispatch in acu_server
e anal.strings=true
e anal.datarefs=true
e anal.jmp.indir=true     ; # function pointer arrays used by JSON dispatch
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
# Standard glibc / libc types
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/errno.h
to libc/signal.h

# Intellian iARM-specific types: cJSON wrappers, bim_user_cfg, UIF protocol
# Path after install.sh: ~/.local/share/radare2/types/intellian/
# Created by corpus_commit.py from r2ghidra pdg analysis.
to intellian/iarm_cgi_structs.h

# glibc zsignatures are loaded by aether_r2profile.py via:
#   profiles/libc/glibc-arm32.r2
# For manual interactive use without the loader:
#   . ~/.local/share/radare2/profiles/libc/glibc-arm32.r2

# ── Magic scans ───────────────────────────────────────────────────────────────
/m /root/.local/share/radare2/magic/crypto_tables.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic

# ── Known symbols — nxagent.cgi (binary hash 55a7d93c…, iARM-nx v2.07) ──────
# Source: vault/Findings/CMD_INJECTION_55a7d93c_1.md
# These are ELF virtual addresses confirmed by the 2026-04-25 analysis session.
# Profile supplements stripped builds where r2 auto-assigns fcn.XXXXXXXX names.
# If the binary has debug symbols r2 already knows these — the flags are harmless.

f sym.NX_Json_Cmd_SENDUIF      @ 0x16234   ; # system() at 0x16348 — UIF cmd passthrough
f sym.NX_Json_Cmd_RUNUIF       @ 0x164dc   ; # 2× system() — UIF + forcesenduif
f sym.JsonCall                 @ 0x23f5c   ; # popen(cmd_field) direct — potential pre-auth
f sym.saveEventLogToPc         @ 0x11bcc   ; # system() via sqlite3 — SQL+OS injection

# ── Known symbols — acu_server (binary hash 2228aacf…, iARM-nx v2.02) ───────
# Source: vault/Findings/CMD_INJECTION_acu_server_2228aacf.md
# acu_server is dynamically linked against libcommon.so.
# Function names below are from r2 auto-naming (fcn.XXXXXXXX) — these are the
# actual discovered addresses, not guesses.

f sym.acu_server_uif_senduif_handler  @ 0x2cd60 ; # sprintf→system: senduif "%s" &
f sym.acu_server_uif_ext_if_dispatch  @ 0x28a58 ; # fork+execl from acu_server.cfg
f sym.acu_server_popen_wrapper        @ 0x27d5c ; # popen() wrapper called with cfg cmds

# ── libcommon.so — shared by nxagent.cgi, acu_server, setagent.cgi ───────────
# escape_expand() is the root-cause function for the auth bypass chain.
# Addresses vary by binary load base — locate at analysis time:
#   r2 libcommon.so; aa; afl~escape_expand,make_acu_auth,check_login
#   axt @ sym.imp.escape_expand     (xrefs to escape_expand from linked binary)
# Known escape_expand flaw: only escapes " and \ — backtick/$()/; pass through.
# See: vault/Findings/CMD_INJECTION_preauth_libcommon_setagent.md

# ── Attack surface summary ────────────────────────────────────────────────────
#
# nxagent.cgi (lighttpd CGI, ports 80/443 HTTPS):
#   Entry:       main() → cgiFormEntries → JSON COMMAND dispatch
#   Auth check:  NX_Json_Check_Login_with_SID() — SID cookie validation
#   Dispatch:    COMMAND field → ~60 handler functions
#   Sinks:       sprintf → system() (120+ calls), sprintf → popen() (6 calls)
#   Pre-auth:    JsonCall (cmd_field → popen directly — confirm auth requirement)
#                LOGIN handler (system() calls during failed auth attempt)
#   Creds:       Default intellian/12345678
#   FTP creds:   Hardcoded upgrader/intellian (firmware update path)
#
# acu_server (TCP:4002 plaintext, TCP:94002 stunnel SSL):
#   Entry:       socket → recv loop → UIF protocol parser
#   Auth check:  make_acu_auth_command() → escape_expand() [BROKEN — CVE pending]
#                Only escapes " and \ — backtick/$()/; injection bypasses auth
#   Sinks:       system() (11 calls), popen() (1 call), execl() (1 call)
#   Key pattern: /bin/nx_monitor_tool senduif "%s" &   [UIF passthrough → RCE]
#                /bin/nx_monitor_tool forcesenduif "%s" &
#   Network:     WiFi SSID JUE-100GX PSK 12345678 → 192.168.2.1:4002
#
# BIM user config:
#   /etc/bim_user.cfg        — BIM authentication credentials
#   /etc/flash/eddy_user.cfg — Eddy web interface user credentials
#   /etc/shadow              — MD5crypt password hashes (root:$1$...)
#
# Pattern references:
#   vault/Findings/CMD_INJECTION_55a7d93c_1.md          (nxagent.cgi)
#   vault/Findings/CMD_INJECTION_acu_server_2228aacf.md (acu_server)
#   vault/Findings/CMD_INJECTION_preauth_libcommon_setagent.md (libcommon.so)
#   vault/Findings/HARDCODED_CRED_GxApp_CLI.md          (CLI creds)

# ── Suggested first r2 commands after loading ─────────────────────────────────
# nxagent.cgi:
#   aa ; afl~NX_Json,JsonCall,saveEvent,Check_Login,ExecuteCommand
#   iz~uif_tool,senduif,intellian,upgrader,sqlite3
#   /c sprintf,popen,system                      # quick sink scan
#   axt @ sym.imp.system                         # all system() call sites
#
# acu_server:
#   aa ; afl~senduif,ext_if,popen,login
#   iz~uif_tool,forcesenduif,acu_tool,auth
#   axt @ sym.imp.system                         # 11 call sites
#   axt @ sym.imp.popen
#
# libcommon.so:
#   aa ; afl~escape,auth,login,ip_address,route

echo "Intellian iARM ARM32 glibc profile loaded."
echo "Attack surface: nxagent.cgi (120+ system() calls), acu_server (TCP:4002), libcommon.so (escape_expand bypass)"
echo "Default creds: intellian/12345678 | FTP: upgrader/intellian"
echo "Refs: CMD_INJECTION_55a7d93c_1.md, CMD_INJECTION_acu_server_2228aacf.md"
