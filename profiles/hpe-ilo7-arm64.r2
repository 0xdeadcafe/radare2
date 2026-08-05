# hpe-ilo7-arm64.r2 — HPE iLO 7 AArch64 PIE C++ BMC Analysis Profile
#
# Target: HPE iLO 7 Integrated Lights-Out BMC firmware
#   SoC:  ARM Cortex-A (AArch64 LE, PIE executable)
#   FS:   HPE TIIF container (see vault/ArchSpecs/hpe_ilo_firmware_decrypt.md)
#         Extracted by: scripts/firmware_decrypt.sh + pre_analyze.sh (TIIF handler)
#   HTTP: restserver — Redfish REST API, port 443 (HTTPS), port 17988 (internal)
#         libweb.so  — shared HTTP session handling, IP-based session bypass
#   Key binaries:
#     restserver (12.5 MB, PIE, C++, ~1481 imports)  — Redfish dispatcher
#     libweb.so  (~2 MB, PIE, C++ shared lib)        — session/auth handling
#
# PLT→GOT note (AArch64 PIE):
#   restserver has 1481 imports. r2's aa may miss PLT stub naming on binaries
#   this large. load_profile() in aether_r2profile.py handles this:
#     1. e bin.plt.resolve=true  (pre-load flag set below)
#     2. aa   (basic analysis)
#     3. aaef (explicit PLT rename pass — fast even on 12.5 MB)
#     4. resolve_aarch64_plt(r2)  (iij ground-truth force-rename for any missed stubs)
#   After this: axtj @ sym.imp.system returns callers correctly.
#   Fallback for persistent failures: /ad bl <plt_addr> scan via get_xrefs().
#
# Selected automatically when:
#   vendor slug = "hpe"  AND  arch = arm/arm64/aarch64  AND  bits = 64
# See: scripts/aether_r2profile.py _VENDOR_PROFILE_MAP
#
# Usage:
#   r2 -i profiles/hpe-ilo7-arm64.r2 restserver
#   Or from within r2: . profiles/hpe-ilo7-arm64.r2

# ── Architecture: AArch64 LE, PIE ────────────────────────────────────────────
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

# PLT→GOT: must be set BEFORE analysis runs (bin.plt.resolve affects ELF loader)
e bin.plt.resolve=true
e anal.jmp.indir=true    ; # follow BR Xn indirect branches (PLT stub pattern)
e anal.calls=true

# ── Analysis tuning ───────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true      ; # C++ vtable dispatch tables in restserver
e anal.strings=true
e anal.datarefs=true
e anal.limits=false      ; # do NOT limit analysis — binary is large by design
# C++ demangling — restserver is compiled with Clang, Itanium ABI
e bin.demangle=true
e anal.cpp.abi=itanium

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

# HPE iLO 7 types: Redfish DataProvider vtable layout, drvsec structs
# TODO: generate types/hpe/ilo7_redfish_structs.h from r2ghidra pdg of restserver.
# After a session with corpus_commit.py, source it here:
# to hpe/ilo7_redfish_structs.h

# ── Magic scans ───────────────────────────────────────────────────────────────
/m /root/.local/share/radare2/magic/crypto_tables.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic

# ── Known primitives (from 2026-04-27 session, Finding: MULTIPLE_bec0b91a) ───
#
# P1: drvsec_execute_cmd — cert import → command execution
#   Function: drvsec_execute_cmd (AArch64, C linkage via extern "C" in header)
#   Sink:     execve() or system() — argument control TBD (aarch64_plt_xref TODO)
#   Status:   REVERSING — argument tracing needed (src: vault/Targets/bec0b91a*.md)
#
# P2: libweb.so IP session bypass — AUTH_BYPASS_libweb_ip_session_supermicro
#   Function: session lookup by IP address match (no token/cookie validation)
#   Auth:     pre-auth if attacker controls source IP or is on same subnet
#   PoC:      chains with existing Supermicro PoCs (supermicro_mbast2500_*)
#
# P3: SSO TrustAll bypass — DOWNGRADED (session must exist; not pre-auth)
# P4: PasswordRecovery — DOWNGRADED (requires iLO management network access)
# P5: LoginHint alt auth path — MEDIUM, alternative auth endpoint unexplored
#
# ── Attack surface summary ────────────────────────────────────────────────────
#
# restserver (AArch64 PIE, C++, 12.5 MB, port 443/17988):
#   Entry:      Redfish REST API dispatcher
#   Auth:       Session token + role enforcement (DataProvider vtable dispatch)
#   Dispatch:   C++ vtable (RTTI: "DataProvider", "CommandDispatcher") — UNRECOVERED_JUMPTABLE
#   Sinks:      execve, system, popen — use aarch64_plt_xref.py to locate all callers
#   r2ghidra:   DO NOT run pdg on mega-functions (15K+ line C++ dispatchers)
#               Use: pdf on specific basic blocks around sink calls only
#   Xrefs:      After load_profile(): axtj @ sym.imp.execve works
#               Alternative:  /ad bl <sym.imp.execve plt_addr>
#
# libweb.so (AArch64 PIE, C++ shared, ~2 MB):
#   Entry:      session_lookup() — searches session table by IP field
#   Flaw:       IP match without token validation → pre-auth session hijack
#   Surface:    Any HTTP request with X-Forwarded-For: <victim_ip>
#               or from same-subnet source IP
#
# iLO management network (port 17988):
#   Requires:   iLO management network access (not internet-exposed)
#   Relevance:  For internal red team or supply chain scenarios
#
# ── Suggested first r2 commands for restserver ───────────────────────────────
# NOTE: aaa on 12.5 MB C++ binary takes 10-20 min and may OOM — DO NOT run aaa.
# Use targeted analysis instead:
#
#   aa                                    ; basic analysis (~60 sec)
#   aaef                                  ; PLT stub rename (~2 sec)
#   #!pipe python3 /aether/scripts/aarch64_plt_xref.py --pipe --sinks system,execve,popen
#   axtj @ sym.imp.execve                 ; get callers after aarch64_plt_xref
#   axt @ sym.imp.drvsec_execute_cmd      ; find all callers of the cert-exec function
#   iz~cert,import,drvsec,execute,command ; locate relevant strings
#   /ad bl sym.imp.system                 ; direct BL scan (fallback)
#
# For C++ vtable hunting (avoids mega-function decompile):
#   iz~DataProvider,CommandDispatcher,drvsec ; find RTTI strings
#   axt @ <rtti_string_addr>              ; find where vtable is constructed
#   pdf @ <vtable_init_func>              ; disassemble (NOT pdg) the init function
#   pf 8*p @ <vtable_addr>               ; dump vtable as 8 function pointers

echo "HPE iLO 7 AArch64 profile loaded."
echo "PLT: e bin.plt.resolve=true set. Run aa + aaef, then aarch64_plt_xref.py."
echo "WARNING: DO NOT run aaa on restserver (12.5 MB C++) — use aa + aaef + targeted analysis."
echo "P1 target: drvsec_execute_cmd — trace cert import argument to execve."
echo "Refs: MULTIPLE_bec0b91a_1.md, AUTH_BYPASS_libweb_ip_session_supermicro.md"
