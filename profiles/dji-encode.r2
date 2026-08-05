# DJI Video Encoder Profile - m0800 (encode_usb)
# Target: TI DaVinci DM365/DM368 (ARM926EJ-S), Linux
# Products: Phantom 3, Inspire video transmission
#
# Usage: r2 -i profiles/dji-encode.r2 firmware.bin
#        Or from r2: . profiles/dji-encode.r2

# Architecture settings
e asm.arch=arm
e asm.bits=32
e asm.cpu=arm926
e cfg.bigendian=false

# ARM9 mode (DaVinci uses ARM, not Thumb)

# Analysis settings for Linux-based firmware
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

# Load DJI format definitions
. /root/.local/share/radare2/format/firmware.pf


# Load DJI magic signatures
/m /root/.local/share/radare2/magic/firmware.magic

# DJI SDK cross-module signatures (sourced from Android ARM32 builds).
# zo dji/DJIDevice.zsig
# zo dji/DJIUavService.zsig


# Load encode_usb symbols (uncomment matching version)
# Note: DJI uses address-based symbols, not zignatures.
# Apply the matching symbol script from symbols/dji/encode_usb/:
# . ~/.local/share/radare2/symbols/dji/encode_usb/P3X_V01.07.0060.r2

# Type definitions
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h

# Visual settings for firmware analysis
e asm.describe=true
e asm.comments=true
e asm.cmt.col=50

# Parse DJI header: pf.dji_imah_header @ 0
