# DJI Lightbridge / OFDM MCU Profile - m0900
# Target: STM32F103 (ARM Cortex-M3)
# Products: Phantom 3, Inspire, Lightbridge systems
#
# Usage: r2 -i profiles/dji-lightbridge.r2 firmware.bin
#        Or from r2: . profiles/dji-lightbridge.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e asm.cpu=cortex
e cfg.bigendian=false

# ARM Thumb mode (STM32F103 uses Thumb)
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

# STM32F103 Lightbridge base address: 0x08008000
# Adjust with: omr 0 0x08008000
# s 0x08008000

# Load DJI format definitions
. /root/.local/share/radare2/format/firmware.pf


# Load DJI magic signatures
/m /root/.local/share/radare2/magic/firmware.magic

# DJI SDK cross-module signatures (sourced from Android ARM32 builds).
# Lightbridge MCU shares RTOS wrappers and comms protocol code with Android SDK.
# zo dji/DJIDevice.zsig
# zo dji/DJIUavService.zsig


# Load Lightbridge symbols (uncomment matching version)
# Note: DJI uses address-based symbols, not zignatures.
# Apply the matching symbol script from symbols/dji/lightbridge/:
# . ~/.local/share/radare2/symbols/dji/lightbridge/P3X_V01.04.0005.r2
# . ~/.local/share/radare2/symbols/dji/lightbridge/P3X_V01.07.0060.r2
# . ~/.local/share/radare2/symbols/dji/lightbridge/P3X_V01.08.0080.r2
# . ~/.local/share/radare2/symbols/dji/lightbridge/P3X_V01.11.0030.r2

# Type definitions (newlib bare-metal — no POSIX socket layer on STM32)
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to embedded/arm-none-eabi/cortex-m.h

# Visual settings for firmware analysis
e asm.describe=true
e asm.comments=true
e asm.cmt.col=50

# Parse DJI header: pf.dji_imah_header @ 0
