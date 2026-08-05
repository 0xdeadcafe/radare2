# DJI Flight Controller (FlyC) Profile - m0306
# Target: STM32F4xx (ARM Cortex-M4), Thumb mode
# Products: Phantom 3/4, Mavic, Spark, Inspire, A3, N3
#
# Usage: r2 -i profiles/dji-flyc.r2 firmware.bin
#        Or from r2: . profiles/dji-flyc.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e asm.cpu=cortex
e cfg.bigendian=false

# ARM Thumb mode (FlyC uses Thumb)
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

# Cortex-M4 base address for FlyC (typical: 0x08020000)
# Adjust with: omr 0 0x08020000
# s 0x08020000

# Load DJI format definitions
. /root/.local/share/radare2/format/firmware.pf


# Load DJI magic signatures  
/m /root/.local/share/radare2/magic/firmware.magic

# zsigs: NOT applicable for FlyC (STM32F4 bare-metal Cortex-M4).
# DJI Android SDK zsigs target Linux/Android ARM32 and will produce false
# positives against Cortex-M Thumb code. Use address-based symbols below.


# Load FlyC function signatures (uncomment matching version)
# Note: DJI uses address-based symbols, not zignatures.
# Apply the matching symbol script from symbols/dji/flyc/:
# . ~/.local/share/radare2/symbols/dji/flyc/wm220_0306.r2
# . ~/.local/share/radare2/symbols/dji/flyc/wm100_0306.r2
# . ~/.local/share/radare2/symbols/dji/flyc/P3X_V01.07.0060.r2

# Type definitions (newlib bare-metal — no POSIX socket layer on STM32)
e dir.types=~/.local/share/radare2/types
to libc/functions.h

# Visual settings for firmware analysis
e asm.describe=true
e asm.comments=true
e asm.cmt.col=50

# Parse DJI header: pf.dji_imah_header @ 0

# Skip encrypted header for analysis (payload starts after header+sig)
# f payload_start = header_size + signature_size
