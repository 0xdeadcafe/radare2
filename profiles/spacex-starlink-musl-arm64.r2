# spacex-starlink-musl-arm64.r2 — SpaceX Starlink user terminal analysis profile
#
# Applies to the entire catson/catapult runtime binary family:
#   user_terminal_frontend (Go, static, gRPC :9200)
#   emc_web_socket_server  (C++, musl, WebSocket :8065)
#   uterm_binbox_user_terminal / connection_manager / umac (C++, musl)
#   user_*.project.so      (C++, musl, hardware variant plugins)
#
# Firmware: catson/catapult 2026.03.27.mr76839.2 (Gauntlet build a2d5a7b6)
# Blob:     2a45edecf2f9ba44b0ad099abd59cf91a14465343e6441a37b5c319bdfa3d353
#
# NOTE: z/ (signature matching) is NOT run automatically — it can take 60-300s
# depending on binary size.  After aa, run it explicitly:
#   r2_cmd(sid, "z/")   # renames fcn.00XXXXX → known musl functions
#   r2_cmd(sid, "aaft") # propagate argument types through call chains

# ---------------------------------------------------------------------------
# Architecture
# ---------------------------------------------------------------------------
e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false
e asm.armfeatures=pauth
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

# Zignature matching thresholds (must be set BEFORE z/ is run)
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# ---------------------------------------------------------------------------
# Type definitions — vendor-specific headers loaded AUTOMATICALLY
# These load instantly and improve decompiler output on every pdg call.
# ---------------------------------------------------------------------------
e dir.types=~/.local/share/radare2/types
to musl/functions.h
to musl/functions-zsig.h
to spacex/starlink.h
to go/runtime.h
to openssl/crypto.h

# ---------------------------------------------------------------------------
# Musl libc signatures — loaded into the zign database but NOT applied yet.
# Run z/ explicitly after aa to apply (see note at top of file).
# ---------------------------------------------------------------------------
zo musl/aarch64/musl-libc.zsig

# ---------------------------------------------------------------------------
# Session symbol files — function renames from prior analysis sessions.
# r2 silently skips . commands for files that don't exist; safe to list all.
# ---------------------------------------------------------------------------
. ~/.local/share/radare2/symbols/spacex/unknown/user_terminal_frontend.r2
. ~/.local/share/radare2/symbols/spacex/unknown/emc_web_socket_server.r2
. ~/.local/share/radare2/symbols/spacex/unknown/uterm_binbox_user_terminal.r2
. ~/.local/share/radare2/symbols/spacex/unknown/connection_manager.r2
. ~/.local/share/radare2/symbols/spacex/unknown/ut_packet_pipeline.r2
. ~/.local/share/radare2/symbols/spacex/unknown/umac.r2
. ~/.local/share/radare2/symbols/spacex/unknown/user_mmut.project.r2
. ~/.local/share/radare2/symbols/spacex/unknown/stsafe_cli.r2
. ~/.local/share/radare2/symbols/spacex/unknown/mlog_service.r2
. ~/.local/share/radare2/symbols/spacex/unknown/user_v4_hp.project.r2
. ~/.local/share/radare2/symbols/spacex/unknown/user_v1.project.r2
. ~/.local/share/radare2/symbols/spacex/unknown/libappmodules.r2

# ---------------------------------------------------------------------------
# Visual
# ---------------------------------------------------------------------------
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# ---------------------------------------------------------------------------
# Key addresses (catapult/catson runtime 2026.03.27.mr76839.2)
#   user_terminal_frontend:
#     HandleRequest dispatcher:    0x62d8d0
#     grpcAuthCounterUpdate gate:  0x529150
#     HandleSensitiveCommand:      0x529d10
#   emc_web_socket_server:
#     emc_prod_check (Slate gate): 0x28430
# ---------------------------------------------------------------------------
