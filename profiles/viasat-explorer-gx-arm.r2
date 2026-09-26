# viasat-explorer-gx-arm.r2 — Viasat Explorer 3075/5075/7100GX ACU Analysis Profile
#
# Targets:
#   Viasat Explorer 3075 / 5075 / 7100GX — ACU binaries (fw 1.61–1.64, ARM32 LE, glibc 2.19)
#   Cobham SAILOR 60GX/100GX — same platform; see also cobham-sailor-arm.r2
#
# This profile extends cobham-sailor-arm.r2 with Explorer GX specific symbols.
# Architecture and analysis settings are identical; the key difference is
# the acu_vmu binary (Explorer GX uses MdmG5/G5 modem protocol, SAILOR uses PTRIA).
#
# Usage:
#   r2 -i profiles/viasat-explorer-gx-arm.r2 acu_vmu
#   Or: r2 -i profiles/cobham-sailor-arm.r2 acu_ctl   (for shared binaries)

# ── Include base SAILOR profile ───────────────────────────────────────────────
. /root/.local/share/radare2/profiles/cobham-sailor-arm.r2 2>/dev/null || true

# ── Known symbols — acu_vmu (binary cab13b2a, Explorer 3075/5075/7100GX fw 1.61b010) ──
# Source: vault/Findings/STACK_OVERFLOW_cab13b2a_1.md (2026-04-24 session)
# MdmG5 = modem protocol handler for Hughes/EchoStar G5 modem.
# Explorer GX uses G5 not PTRIA (SAILOR uses PTRIA on binary 539e9d11).

f sym.MdmG5__DecodeIp              @ 0x00020f2c  ; # sscanf %32s into 32-byte buf → strcpy — OVERFLOW
f sym.HandleScAcunsMessage         @ 0x00022af0  ; # dispatches decoded modem messages
f sym.viReceiveUdp                 @ 0x00019660  ; # recvfrom(udp_fd, buf, 500) → vtable → MdmG5
f sym.vcUpdateNetworkSetup         @ 0x0         ; # called after DecodeIp with corrupted struct
# vmu_network_setup_t: {ip[16], mask[16], gw[16], dns[16]} on caller stack
# strcpy into dns[16] with up to 32 bytes → overwrites r4..r8 on caller stack

# Debug shell (acu_vmu):
# tcp*127.0.0.1*2327 — VMU debug shell, same tt_cshell framework as acu_ctl
# Locate: iz~tcp*127.0.0.1*2327

# ── PTRIA protocol (acu_vmu binary 539e9d11, SAILOR 60GX fw 1.64B016) ────────
# Source: vault/Findings/CMD_INJECTION_539e9d11_1.md
# PTRIA is Viasat's modem protocol on TCP:6999 (mutual TLS required).
# Explorer GX uses G5/G4 UDP modem protocol instead (different binary variant).

f sym.MdmPtria__handleGenMsg           @ 0x0  ; # type 0 = firmware install, type 7 = CRL
f sym.handle_gen_data_xfer_chunk       @ 0x3467c  ; # writes /tmp/upload → c_install_image
f sym.c_install_image                  @ 0x3bd1c  ; # system("acu_cman.sh install /tmp/upload")
# PTRIA firmware install: only CRC32 validated — no signature check (same suu bug)

# ── Explorer GX attack surface notes ─────────────────────────────────────────
#
# Pre-auth command injection (acu_web) — identical to SAILOR GX:
#   snprintf → "pwutil -v <user> -- \"<pass>\"" → proc_run → CMD_INJECTION
#
# acu_vmu DecodeIp overflow (modem-serial interface):
#   Attacker requires modem-side access (compromised modem or MITM on modem-ACU link)
#   %32s into 32-byte local buf → NUL off-by-one on r4 low byte
#   strcpy(dns[16], 32-char input) → overwrites caller r4..r8 (data corruption / DoS)
#   Actual PC control NOT directly achievable through this path alone — downgraded to Medium
#   Chain with /tmp/admin bypass + pwutil -c for root password change instead
#
# cbus_server (local, zero auth) — identical to SAILOR:
#   CBUS type 8 → AduIfImpl::dispatch → strcpy(obj+0x31d4, payload) — heap overflow
#   Chain: acu_web RCE → cbus UNIX socket → heap overflow → control flow
#
# Telnet root shell (ALL Explorer GX versions):
#   /etc/inetd.conf: telnetd root, tcp port 23
#   Default shadow: root:$1$CD2rl.N.$StKfO0sHtb/... (MD5crypt — CRACKED: see loot/)
#
# Suggested commands for acu_vmu (Explorer GX):
#   aa ; s sym.MdmG5__DecodeIp ; pdg          ; # decompile DecodeIp
#   axt @ sym.MdmG5__DecodeIp                 ; # find all callers
#   s sym.HandleScAcunsMessage ; pdf           ; # disassemble message dispatcher
#   iz~DecodeIp,G5,modem,IP#,MASK#            ; # confirm format strings

echo "Viasat Explorer GX ARM32 profile loaded (extends cobham-sailor-arm.r2)."
echo "Extra symbols: MdmG5::DecodeIp (overflow), HandleScAcunsMessage, viReceiveUdp"
echo "Refs: STACK_OVERFLOW_cab13b2a_1, CMD_INJECTION_539e9d11_1"
