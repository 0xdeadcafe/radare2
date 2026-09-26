# cobham/ — Cobham / Thrane & Thrane (Viasat) type definitions
#
# Target: Viasat SAILOR TT-7xxx ACU platform
#   Products: SAILOR 60GX, SAILOR 100GX, Explorer 3075/5075/6075/7100GX,
#             SAILOR 600/900/1000 VSAT GX
#   Arch:     ARM32 LE Linux (uClibc fw 1.61-1.64; musl-like fw 1.66+)
#   Mitigations: NONE across all versions (no canary, no NX, no PIE, no RELRO)
#
# Files:
#   tt_cshell.h — tt_cshell debug shell types, vmu_network_setup_t (DecodeIp overflow),
#                 PTRIA protocol structs, TIIF firmware image format, CBUS IPC messages,
#                 suu validation function declarations
#
# Planned future profile (not yet written):
#   profiles/cobham-sailor-arm.r2 — auto-loads this header
#
# Basis (all from 2026-04-24/25 analysis sessions):
#   - vault/Findings/CMD_INJECTION_99fda815_1.md      (acu_ctl tt_cshell)
#   - vault/Findings/CMD_INJECTION_539e9d11_1.md      (acu_vmu SAILOR 60GX PTRIA)
#   - vault/Findings/STACK_OVERFLOW_cab13b2a_1.md     (acu_vmu Explorer GX DecodeIp)
#   - vault/Findings/UNSIGNED_FW_069d7d9a_suu_tiif.md (suu TIIF CRC32-only)
#   - vault/Findings/VULN_MATRIX_tt7xxx_cross_version.md
#   - vault/Patterns/Cobham_tt_cshell_System_Exec.md
#   - vault/Patterns/SUID_Firmware_CRC32_Only.md
#
# Usage in r2:
#   to cobham/tt_cshell.h
#   aaft                          (apply types to imported functions)
#   ts vmu_network_setup_t        (verify struct layout)
#   ts tiif_header_t              (TIIF file header)
#   ts tiif_content_header_t      (TIIF content part header)
