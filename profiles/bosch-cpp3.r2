# Bosch CPP3 Platform Analysis Profile
# Target:  Bosch VIP X Series H.264 Video Server — CPP3 hardware platform
# CPU:     ARM Cortex-A (ARM32 LE)
# OS:      Proprietary RTOS (statically linked modules, no shared lib imports)
# Modules: arm.app1 (base 0xc0080000), webservice.dll (base 0xc7e00000),
#          rtsp.dll (base 0xc7e00000)
# Container: XOR-obfuscated DLL modules (key: 0x42, magic DEADAFFE format)
#
# Confirmed from finding: 12abfda8 (VIP X series H.264, fw 5.97.0013)
# Status: POC_FOUND
#
# Usage:
#   r2 -i profiles/bosch-cpp3.r2 arm.app1
#   For DLL modules: r2 -m 0xc7e00000 -i profiles/bosch-cpp3.r2 webservice.dll

# =============================================================================
# Architecture
# =============================================================================
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# =============================================================================
# Analysis settings
# =============================================================================
# Statically linked — no PLT/GOT, no dynamic section
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true
e anal.datarefs=true

# Zignature matching thresholds (lower defaults so manual zo+z/ works)
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4
e bin.demangle=true

# =============================================================================
# Type definitions
# =============================================================================
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl-arm32.h
to libc/errno.h

# =============================================================================
# Memory map notes
#
# arm.app1 base:        0xc0080000 (main application)
# webservice.dll base:  0xc7e00000 (HTTP/CGI server module)
# rtsp.dll base:        0xc7e00000 (RTSP streaming module — loaded separately)
#
# To rebase a DLL module:
#   omr 0 0xc7e00000
# =============================================================================

# =============================================================================
# Crypto/protocol scan
# =============================================================================
/m /root/.local/share/radare2/magic/crypto_tables.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic

# =============================================================================
# Display
# =============================================================================
e asm.describe=true
e asm.comments=true
e asm.cmt.col=55

?e [bosch-cpp3] ARM32 LE profile loaded. Statically linked RTOS — no PLT.
?e [bosch-cpp3] Rebase DLL modules: omr 0 0xc7e00000
?e [bosch-cpp3] Container XOR key: 0x42 (DEADAFFE magic)
