# furuno-felcom-arm.r2 — Furuno FELCOM 251/501 BDU Analysis Profile
#
# Target: Furuno FELCOM 251 / 501 BDU (Broadband Data Unit)
#   Firmware: bdu_0104 (v0.1.04)
#   SoC:      ARM Cortex-A (ARMv7-A LE, Thumb-2), Linux
#   FS:       SquashFS partitions (squashfs-root-0, squashfs-root-1)
#   HTTP:     Crow C++ HTTP framework on lighttpd — not standard CGI
#   Key:      ap_json_api (C++ daemon, JSON-RPC over HTTP)
#             privcmd_api (privileged command interface)
#
# Note: ap_json_api is also present in Cobham Explorer 710 (cobham-e710-api.r2).
# The FELCOM version shares the same CwpFileUtil/ServicePathHandler framework.
# Use cobham-e710-api.r2 for Explorer 710 analysis; use this profile for FELCOM.
#
# Selected automatically when:
#   vendor slug = "furuno"  AND  arch = arm  AND  bits = 32
# See: scripts/aether_r2profile.py _VENDOR_PROFILE_MAP ("arm","32","furuno")
#
# Usage:
#   r2 -i profiles/furuno-felcom-arm.r2 ap_json_api
#   r2 -i profiles/furuno-felcom-arm.r2 privcmd_api

# ── Architecture: ARM32 LE, ARMv7-A Thumb-2 ──────────────────────────────────
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false
e asm.cpu=cortex-a7
e anal.cc=arm               ; # ARM EABI5 calling convention

# ── Analysis tuning ───────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true         ; # C++ vtable dispatch in ServicePathHandler and AuthController
e anal.strings=true
e anal.datarefs=true
e anal.jmp.indir=true       ; # C++ virtual dispatch via vtable function pointers
e anal.limits=false

# C++ demangling (Itanium ABI — ARM Linux GCC default)
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
to libc/fcntl-arm32.h
to libc/errno.h
to libc/signal.h

# ── Zignatures ────────────────────────────────────────────────────────────────
# This vendor profile relies on the libc auto-layer loaded by aether_r2profile.py:
#   glibc  -> profiles/libc/glibc-arm32.r2
#   musl   -> profiles/libc/musl-arm32.r2
# For manual interactive use without aether_r2profile.py, source the matching libc layer:
#   . ~/.local/share/radare2/profiles/libc/glibc-arm32.r2
#   . ~/.local/share/radare2/profiles/libc/musl-arm32.r2

# ── Magic scans ───────────────────────────────────────────────────────────────
/m /root/.local/share/radare2/magic/crypto_tables.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic

# ── Known symbols — ap_json_api (FELCOM 251/501, fw bdu_0104) ────────────────
# Sources:
#   vault/Findings/CMD_INJECTION_ap_json_api_01.md     (system() sink)
#   vault/Findings/STACK_OVERFLOW_ap_json_api_02.md    (strcpy CwpFileUtil)
# All addresses are ARM32 VAs in the stripped ELF.

# CMD_INJECTION: ServicePathHandler::updateOperation (at 0x82378)
f method.ServicePathHandler.updateOperation    @ 0x82378  ; # builds system() cmd from req params
f method.ServicePathHandler.updateOperation_rce@ 0x8242c  ; # bl sym.imp.system ← INJECTION SINK
# Route: POST /api/service/update → ServicePathHandler::handleRequest → updateOperation

# STACK_OVERFLOW: CwpFileUtil::checkFilePath (at 0x56c84)
f method.CwpFileUtil.checkFilePath             @ 0x56c84  ; # strcpy(stack_512, user_path) — OVERFLOW
f method.CwpFileUtil.checkFilePath_strcpy      @ 0x56cb8  ; # bl sym.imp.strcpy ← OVERFLOW SITE
f method.CwpFileUtil.putFileChunk              @ 0x56e84  ; # caller → checkFilePath
f method.FileHandler.fileUpload                @ 0x4e078  ; # entry → putFileChunk
f method.FileHandler.handleRequest             @ 0x4e620  ; # route dispatch entry
f method.FileHandler.tryFile                   @ 0x4e4d0  ; # inner file lookup

# Authentication
f method.AuthenticationHandler.authenticate    @ 0x4e888  ; # session token validation
f method.AuthenticationHandler.execLoginHook   @ 0x4f260  ; # login hook → system() call
f method.AuthenticationHandler.execLogoutHook  @ 0x4f528  ; # logout hook → system() call
f method.AuthController.authenticate           @ 0x4fb20  ; # alternative auth controller
f method.AuthController.execLoginHook          @ 0x50308  ; # login → system()
f method.AuthController.execLogoutHook         @ 0x506e4  ; # logout → system()

# Access control / path normalisation
f method.AccessMap.mayRead                     @ 0x4b590  ; # access check (read path)
f sym.normalizeString                          @ 0x4c518  ; # string normalisation helper

# Process spawning infrastructure
f method.Process.spawn                         @ 0x63798  ; # generic fork+exec wrapper
f method.RPCSocketMonitor.listen               @ 0x63020  ; # JSON-RPC socket listener

# Dangerous imports (PLT entries at confirmed addresses for Explorer 710 variant)
# FELCOM addresses may differ by 1-2 KB due to binary version differences
f sym.imp.system   @ 0x48be0   ; # from cobham-e710-api.r2 — verify with: iij~system
f sym.imp.popen    @ 0x486c4   ; # from cobham-e710-api.r2 — verify with: iij~popen
f sym.imp.strcpy   @ 0x0       ; # locate with: iij~strcpy

# ── Known symbols — privcmd_api (FELCOM 251/501) ──────────────────────────────
# Source: vault/Findings/CMD_INJECTION_privcmd_api_03.md
# privcmd_api is a privileged command interface accessed via JSON-RPC over local socket.
# Details: TODO — binary not yet deeply analysed. Locate with:
#   iz~privcmd,exec,system,popen
#   axt @ sym.imp.system ; axt @ sym.imp.popen

f sym.privcmd_api_entry @ 0x0  ; # resolve at analysis time

# ── Attack surface summary ────────────────────────────────────────────────────
#
# ap_json_api (HTTP, port 80/443):
#   Entry:    Crow HTTP framework → route dispatch → C++ handler virtual dispatch
#   Auth:     Session token (AuthenticationHandler::authenticate)
#             Default credentials: admin/admin or admin/furuno (check /etc/bim_user.cfg)
#
#   V1 — CMD_INJECTION via ServicePathHandler::updateOperation:
#     Route:  POST /api/service/update (requires auth)
#     Path:   handleRequest → updateOperation → sprintf(buf, "%s %s", cmd, param) → system()
#     Impact: Authenticated OS command injection → root (process runs as root)
#
#   V2 — STACK_OVERFLOW in CwpFileUtil::checkFilePath:
#     Route:  POST /api/file/upload (requires auth — file upload API)
#     Path:   fileUpload → putFileChunk → checkFilePath → strcpy(stack_512, user_path)
#     Buffer: 512-byte stack buffer at checkFilePath stack frame
#     Impact: Post-auth stack overflow → ROP → root
#     Note:   Binary has NO stack canary confirmed (rabin2 -I ap_json_api → canary: false)
#             ARM32 LE — shellcode or ret2libc via glibc gadgets
#
# privcmd_api (local socket):
#   Entry:  JSON-RPC over local UNIX socket
#   Auth:   None or trivial local credentials (TODO — needs deeper analysis)
#   Likely: Further post-auth elevation or lateral movement vector
#
# Mitigations:
#   ap_json_api: NO stack canary, Thumb-2 ARM32, stripped
#   privcmd_api: TODO

# ── Suggested first r2 commands ───────────────────────────────────────────────
# For ap_json_api:
#   aa ; aaef                                     ; # analysis + PLT rename
#   axt @ sym.imp.system                          ; # find all system() callers
#   axt @ sym.imp.strcpy                          ; # find strcpy callers (including checkFilePath)
#   s method.ServicePathHandler.updateOperation ; pdg   ; # decompile CMD_INJECTION
#   s method.CwpFileUtil.checkFilePath ; pdg      ; # decompile STACK_OVERFLOW
#   iz~updateOperation,checkFilePath,system(      ; # find format string templates
#   iz~ChangePasswd,script,cmd,api/               ; # find other command execution paths
#
# C++ vtable hunting:
#   iz~ServicePathHandler,CwpFileUtil,FileHandler ; # find RTTI strings
#   axt @ <rtti_addr>                             ; # find vtable construction
#   pf 8*p @ <vtable_addr>                        ; # dump vtable function pointers

echo "Furuno FELCOM 251/501 ARM32 profile loaded."
echo "Key targets: ap_json_api (C++ HTTP/JSON-RPC), privcmd_api (privileged IPC)"
echo "V1: CMD_INJECTION ServicePathHandler::updateOperation → system() @ 0x8242c"
echo "V2: STACK_OVERFLOW CwpFileUtil::checkFilePath → strcpy(stack_512) @ 0x56cb8"
echo "Refs: CMD_INJECTION_ap_json_api_01, STACK_OVERFLOW_ap_json_api_02"
