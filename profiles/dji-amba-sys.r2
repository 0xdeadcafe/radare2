# DJI Ambarella System Partition Profile - m0100
# Target: Ambarella A9SE (ARM Cortex-A9), Linux
# Products: Phantom 3/4 Camera systems
#
# Usage: r2 -i profiles/dji-amba-sys.r2 firmware.bin
#        Or from r2: . profiles/dji-amba-sys.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e asm.cpu=cortex
e cfg.bigendian=false

# ARM mode (Ambarella uses ARM, not Thumb)

# Analysis settings for larger Linux-based firmware
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.jmp.indir=true
e anal.datarefs=true
e anal.strings=true
e anal.depth=64

# Zignature matching thresholds (lower defaults so manual zo+z/ works)
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# Ambarella A9 typical base address: 0x0E600000
# Adjust with: omr 0 0x0E600000
# s 0x0E600000

# Load DJI format definitions
. /root/.local/share/radare2/format/firmware.pf


# Load DJI magic signatures
/m /root/.local/share/radare2/magic/firmware.magic

# DJI SDK cross-module signatures (sourced from Android ARM32 builds).
# These cover duss_osal_*, RTOS wrappers, and SDK base functions present
# in Ambarella Linux modules that share code with the Android SDK.
# Lower confidence than address-based symbols; use z/ then verify with axt.
# zo dji/DJIDevice.zsig
# zo dji/DJIUavService.zsig


# Load Ambarella system symbols (uncomment matching version)
# Note: DJI uses address-based symbols, not zignatures.
# Apply the matching symbol script from symbols/dji/amba_sys/:
# . ~/.local/share/radare2/symbols/dji/amba_sys/P3X_V01.01.0008.r2
# . ~/.local/share/radare2/symbols/dji/amba_sys/P3X_V01.08.0080.r2
# . ~/.local/share/radare2/symbols/dji/amba_sys/P3X_V01.11.0030.r2

# Type definitions
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h

# Visual settings for firmware analysis
e asm.describe=true
e asm.comments=true
e asm.cmt.col=50

# Parse Ambarella headers: pf.amba_part_header, pf.amba_romfs_header
# Parse DJI header: pf.dji_imah_header @ 0
