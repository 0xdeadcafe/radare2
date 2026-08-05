# DJI Android ARM32 (armeabi-v7a / Thumb-2) Analysis Profile
# Targets: wm240 (Mavic 2 Pro), wm231 (Mavic Air 2), wm232 (Mavic Air 2S),
#          wm160 (Mavic Mini), wm169 (Avata), wm1695 (O3 Air Unit)
#          — any DJI product running Android 6+ on Qualcomm/Allwinner Eagle SoC
#
# Loaded automatically when: arch=arm, bits=16 or 32, vendor=dji
# Manual usage: r2 -i profiles/dji-android-arm32.r2 dji_sys

# ── Architecture ──────────────────────────────────────────────────────────────
# Force 32-bit even if r2 auto-detected bits=16 (Thumb-2 .so detection artifact).
# Thumb-2 instructions decode correctly with bits=32 + asm.cpu=cortex.
e asm.arch=arm
e asm.bits=32
e asm.cpu=cortex
e cfg.bigendian=false

# ── Analysis ─────────────────────────────────────────────────────────────────
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.jmp.indir=true
e anal.strings=true
e anal.datarefs=true
e bin.demangle=true

# ── Zignature matching ────────────────────────────────────────────────────────
e zign.graph=true
e zign.refs=true
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4

# ── Android bionic libc types ─────────────────────────────────────────────────
e dir.types=~/.local/share/radare2/types
to android/jni.h
to android/functions.h

# Standard libc function signatures (socket, recv, system, popen, etc.)
to libc/functions.h
to libc/socket.h
to libc/errno.h
to libc/fcntl-arm32.h
to libc/signal.h

# ── DJI DUML / DUPC type definitions ─────────────────────────────────────────
# DUPC 0x55 packet structs, IMaH module headers, cmd_set/cmd_id enums,
# duss_event_msg_t dispatcher struct.
to dji/dji-common.h
to dji/dji-structs.h

# ── NDK libc zignatures (ARM EABI v7a) ───────────────────────────────────────
# Matches strlen, memcpy, snprintf, etc. auto-labelled in stripped binaries.
zo android/armeabi-v7a/ndk-r27c.zsig

# ── Visual / output settings ─────────────────────────────────────────────────
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60

# ── Usage notes ───────────────────────────────────────────────────────────────
# After . profile / r2_open init_cmds:
#   aa           — full analysis (Thumb-2 functions correctly identified)
#   tp duss_event_msg_t @ <msg_ptr>    — format DUPC event message
#   tp dji_dupc55_full @ <pkt_ptr>     — format DUPC 0x55 packet header
#   afl~dji,duss,mb_                   — find DJI framework functions
#   ii~system,popen,recv               — locate dangerous sinks immediately
#
# Known binaries for this profile:
#   dji_sys      de2cc34b  wm240 V01.00.0400  360996 B
#   libduml_frwk 8073dc82  wm240 V01.00.0400  523560 B
#   dji_flight   fb2c567d  wm240 V01.00.0400  599612 B
#   dji_camera2  c2c74bbd  wm240 V01.00.0400  623000 B
