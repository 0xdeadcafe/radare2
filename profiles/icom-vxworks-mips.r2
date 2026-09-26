# Icom AP-90M v2 / VxWorks 6.9 MIPS32 BE — discovered 2026-05-22 from 8fbb6d21
# Binary: vxworks_kernel.bin (decompressed)
# Usage: r2 -a mips -b 32 -e cfg.bigendian=true -m 0x80000000 vxworks_kernel.bin
e asm.arch=mips
e asm.bits=32
e cfg.bigendian=true
# NOTE: flat binary — use '-m 0x80000000' flag at open time, NOT e bin.baddr
# GP register: 0x80e136d0 (loaded via lui gp, 0x80e1; addiu gp, gp, 0x36d0)
# Symbol table: linear scan at 0x80c61xxx / 0x80c8xxxx (20-byte entries)
# Symbol entry: [u32 flags][u32 group][u32 name_ptr][u32 value_ptr][u32 reserved]
# RSAP2 method string table: 0x8073e5c8 (SHELL, CONFIG, FIRMUP, ...)
# Key functions: rsap2_method_shell=0x8051ff9c, rsap2_send_notify=0x80495200

# Type definitions
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/signal.h
to vxworks/vxworks.h
