# Bosch CPP-ENC VIP X Platform Analysis Profile
# Target:  Bosch VIP X series — CPP-ENC (encrypted/obfuscated) firmware modules
# CPU:     ARM Cortex-M (Thumb-2 LE), base 0x80000000
# OS:      Proprietary bare-metal / embedded RTOS
# Format:  Proprietary module container:
#            - Main image magic: 0x80020000
#            - DLL magic: 0xC200
#            - r2/rabin2 cannot auto-detect — must open as raw with -b 16
#
# Confirmed from finding: a082bf81 (Bosch VIP X, CPP-ENC platform)
# Status: POC_FOUND
#
# Usage:
#   r2 -b 16 -i profiles/bosch-cppenc.r2 firmware.bin
#   Then rebase: omr 0 0x80000000

# =============================================================================
# Architecture — ARM Thumb-2
# =============================================================================
e asm.arch=arm
e asm.bits=32
e asm.thumb=true
e cfg.bigendian=false

# =============================================================================
# Analysis settings
# =============================================================================
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.jmp.indir=true
e anal.strings=true
e anal.datarefs=true
e bin.demangle=true

# Cortex-M analysis optimizations
# anal.cjmp.off helps with Thumb-2 conditional branches used as tail calls
e anal.cjmp.off=true

# Zignature matching thresholds (lower defaults so manual zo+z/ works)
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

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
# Flat binary load address: 0x80000000
# After opening raw binary:
#   omr 0 0x80000000    — rebase to correct VA
#   ahb 16             — force Thumb mode if auto-detect misses it
#
# Module identification:
#   Main image: first 4 bytes = 0x80020000 (little-endian)
#   DLL module: first 2 bytes = 0xC200
#
# The proprietary module format wraps a Thumb-2 ELF or flat binary.
# After stripping the container header, analysis proceeds as ARM Thumb-2.
# =============================================================================

# Rebase flat binary
omr 0 0x80000000

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

?e [bosch-cppenc] ARM Thumb-2 LE raw binary profile loaded.
?e [bosch-cppenc] If binary not rebased: omr 0 0x80000000
?e [bosch-cppenc] If Thumb mode missing: ahb 16
