# supermicro/ — Supermicro BMC type definitions
#
# Target: Supermicro MBAST2500 BMC (Aten OEM firmware, ARM926EJ-S, IPMI fw 5.72.32)
#
# Files:
#   bmc_structs.h — tag_dispatch_entry_t, ipmi_session_t, web_session_entry_t,
#                   cgiGetPostVariable / GetValue declarations, tiif overflow constants
#
# Auto-loaded by: profiles/supermicro-bmc-arm.r2
#
# Basis (all from 2026-04-24 analysis session):
#   - vault/Findings/STACK_OVERFLOW_acac7f0a_ipmi_cgi_preauth.md
#   - vault/Findings/SYSTEMIC_OVERFLOW_libipmi_cgiGetPostVariable.md
#   - vault/Findings/AUTH_BYPASS_libweb_ip_session_supermicro.md
#   - vault/Patterns/CGI_Tag_Dispatch_Auth_Bypass.md
#
# Usage in r2:
#   to supermicro/bmc_structs.h
#   aaft   (apply types to imported functions)
#   ts tag_dispatch_entry_t   (verify struct layout)
#   tp tag_dispatch_entry_t @ 0x2FED8   (print entry 58 in ipmi.cgi)
