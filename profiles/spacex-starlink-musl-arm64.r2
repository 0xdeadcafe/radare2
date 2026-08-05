# spacex-starlink-musl-arm64.r2 — SpaceX Starlink user terminal analysis profile
#
# Applies to the entire catson/catapult runtime binary family:
#   user_terminal_frontend (Go, static, gRPC :9200)
#   emc_web_socket_server  (C++, musl, WebSocket :8065)
#   uterm_binbox_user_terminal (C++, musl, multi-call)
#   connection_manager     (C++, musl, PoP tunnel + STSafe HSM)
#   user_*.project.so      (C++, musl, hardware variant plugins)
#   ut_packet_pipeline, umac, phyfw* (C++, musl, data plane)
#
# Usage (from r2 session):
#   . ~/.local/share/radare2/profiles/spacex-starlink-musl-arm64.r2
#
# Usage (from skill):
#   r2_cmd ". /opt/aether/skel/.local/share/radare2/profiles/spacex-starlink-musl-arm64.r2"
#
# Firmware: catson/catapult 2026.03.27.mr76839.2 (Gauntlet build a2d5a7b6)
# Blob:     2a45edecf2f9ba44b0ad099abd59cf91a14465343e6441a37b5c319bdfa3d353
# SoC:      STM-based (catson), AArch64 application core
# Mitigations: PAC (PACIA/RETAA), stack canary, PIE (except user_terminal_frontend)

# ---------------------------------------------------------------------------
# Architecture
# ---------------------------------------------------------------------------
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

# AArch64 pointer authentication (PACIA/PACIASP/RETAA/RETAB present in all binaries)
# r2 strips PAC bits automatically on aarch64; this is informational
e asm.armfeatures=pauth

# ---------------------------------------------------------------------------
# PLT/GOT resolution for PIE binaries (NOT user_terminal_frontend — static)
# ---------------------------------------------------------------------------
e bin.plt.resolve=true

# ---------------------------------------------------------------------------
# Analysis settings
# ---------------------------------------------------------------------------
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e anal.calls=true
e anal.fcn.maxref=512
e bin.demangle=true
e bin.demanglecmd=true

# Zignature settings
e zign.graph=true
e zign.refs=true
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4

# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
to spacex/starlink.h

# ---------------------------------------------------------------------------
# Musl libc signatures (shared by all C++ binaries in this family)
# ---------------------------------------------------------------------------
zo musl/aarch64/musl-libc.zsig

# ---------------------------------------------------------------------------
# Symbol files (named functions from analysis sessions)
# Apply only the file matching the binary being analysed; all are listed here
# for reference — r2 skips . commands for files that don't exist yet.
# ---------------------------------------------------------------------------
# user_terminal_frontend  (Go static, gRPC :9200)
# . ~/.local/share/radare2/symbols/spacex/unknown/user_terminal_frontend.r2
#
# emc_web_socket_server   (C++ musl, WebSocket :8065)
# . ~/.local/share/radare2/symbols/spacex/unknown/emc_web_socket_server.r2
#
# uterm_binbox_user_terminal  (C++ musl, multi-call)
# . ~/.local/share/radare2/symbols/spacex/unknown/uterm_binbox_user_terminal.r2
#
# user_mmut.project.so    (C++ musl, MMUT plugin)
# . ~/.local/share/radare2/symbols/spacex/unknown/user_mmut.project.r2

# ---------------------------------------------------------------------------
# Visual settings
# ---------------------------------------------------------------------------
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# ---------------------------------------------------------------------------
# After loading, recommended analysis sequence:
#
# For user_terminal_frontend (16.7 MB Go static — use targeted analysis):
#   aae                ; find entry points and basic blocks only
#   /c bl              ; find all call sites without full aa
#   . ~/.local/share/radare2/symbols/spacex/unknown/user_terminal_frontend.r2
#   s 0x62d8d0         ; seek to HandleRequest (gRPC main dispatcher)
#   pdc                ; decompile with r2ghidra
#
# For emc_web_socket_server (1.1 MB C++ musl — full aa feasible):
#   aaa
#   . ~/.local/share/radare2/symbols/spacex/unknown/emc_web_socket_server.r2
#   s 0x28430          ; seek to emc_prod_check (Slate auth gate)
#   pdf
#
# For user_*.project.so (shared library — use iE for exports):
#   iE                 ; list exports (controlcode_* are the entry points)
#   s sym.controlcode_execute
#   pdc
# ---------------------------------------------------------------------------
