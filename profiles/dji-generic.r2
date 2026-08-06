# DJI Generic Firmware Profile
# Use when module type is unknown or for initial exploration
#
# Usage: r2 -i profiles/dji-generic.r2 firmware.bin
#        Or from r2: . profiles/dji-generic.r2

# Architecture settings (ARM 32-bit, auto-detect Thumb)
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# Analysis settings for firmware
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.jmp.indir=true
e anal.datarefs=true
e anal.strings=true

# Zignature matching thresholds (lower defaults so manual zo+z/ works)
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# Load DJI type definitions — DUPC packet structs + command set enums
e dir.types=~/.local/share/radare2/types
to dji/dji-common.h
to dji/dji-structs.h
to libc/functions.h
to embedded/arm-none-eabi/cortex-m.h

# FreeRTOS RTOS kernel + Newlib libc zsigs for bare-metal Cortex-M targets.
# Covers CM0/M0+ (ARMv6-M) and CM7 (ARMv7E-M) which lack dedicated profiles.
# CM3 and CM4 are handled by dji-gimbal.r2 and dji-flyc.r2 respectively.
zo embedded/arm-none-eabi/freertos-cm0.zsig
zo embedded/arm-none-eabi/newlib-v6m.zsig
zo embedded/arm-none-eabi/freertos-cm7.zsig

# Load firmware format struct definitions (pf.dji_imah_header, pf.dji_dupc55_full, etc.)
. /root/.local/share/radare2/format/firmware.pf

# Magic scans — identify protocol handlers and crypto tables in this binary
/m /root/.local/share/radare2/magic/firmware.magic
/m /root/.local/share/radare2/magic/proto_fingerprint.magic
/m /root/.local/share/radare2/magic/crypto_tables.magic

# Visual settings for firmware analysis
e asm.describe=true
e asm.comments=true
e asm.cmt.col=50

# Parse DJI headers:
#   pf.dji_imah_header @ 0      - IM*H signed module
#   pf.dji_imah_chunk           - Chunk headers
#   pf.dji_xv4_header @ 0       - xV4 firmware package
#   pf.dji_xv4_entry            - xV4 module entries
#   pf.dji_dupc55_full          - DUPC 0x55 packets
#   pf.dji_dupcab_hdr           - DUPC 0xAB packets

# Module type identification:
#   0100 = Camera/Ambarella     -> use dji-amba-sys.r2
#   0306 = Flight Controller    -> use dji-flyc.r2
#   0400 = Gimbal               -> use dji-gimbal.r2
#   0800 = Video Encoder        -> use dji-encode.r2
#   0900 = Lightbridge          -> use dji-lightbridge.r2
#   1400 = Ground MCU           -> use dji-gimbal.r2
