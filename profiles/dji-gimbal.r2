# DJI Gimbal Controller Profile - m0400, m1400, m1401
# Target: STM32F103 (ARM Cortex-M3) / LPC1765 (ARM Cortex-M3)
# Products: Phantom 3/4, Inspire, Lightbridge 2
#
# Usage: r2 -i profiles/dji-gimbal.r2 firmware.bin
#        Or from r2: . profiles/dji-gimbal.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e asm.cpu=cortex
e cfg.bigendian=false

# ARM Thumb mode (gimbal MCUs use Thumb)
ahb 16

# Analysis settings optimized for embedded firmware
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

# Base addresses vary by module:
# m0400 (gimbal air): typically 0x08000000
# m1400 (LPC1765 ground): typically 0x0000A000
# m1401 (LPC1765 ground): typically 0x0000A000

# Load DJI format definitions
. /root/.local/share/radare2/format/firmware.pf


# Load DJI magic signatures
/m /root/.local/share/radare2/magic/firmware.magic

# DJI SDK cross-module signatures.
# Gimbal MCU is bare-metal Cortex-M3 — DJI Android zsigs do not apply here.
# FreeRTOS CM3 + Newlib zsigs name RTOS kernel and libc functions.
zo embedded/arm-none-eabi/freertos-cm3.zsig
zo embedded/arm-none-eabi/newlib-v7m.zsig


# Load gimbal symbols (uncomment matching version)
# Note: DJI uses address-based symbols, not zignatures.
# Apply the matching symbol script from symbols/dji/gimbal/:
# . ~/.local/share/radare2/symbols/dji/gimbal/C1_V01.05.0080.r2
# . ~/.local/share/radare2/symbols/dji/gimbal/C1_V01.06.0000.r2

# Type definitions (newlib bare-metal — no POSIX socket layer on STM32)
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to embedded/arm-none-eabi/cortex-m.h

# Visual settings for firmware analysis
e asm.describe=true
e asm.comments=true
e asm.cmt.col=50

# Parse DJI header: pf.dji_imah_header @ 0
