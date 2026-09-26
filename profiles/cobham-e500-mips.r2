# r2 profile: Cobham BGAN Explorer 500/300 (MIPS Big Endian, eCos)
# Flat binary, no ELF headers. Load at file offset 0x0.
# Virtual base address: 0x80000000 (from lui k1, 0x8000 in exception vector)
#
# Usage: r2 -i profiles/cobham-e500-mips.r2 MAIN_CPU.bin
#   or:  r2 -a mips -b 32 -e cfg.bigendian=true MAIN_CPU.bin
#        . profiles/cobham-e500-mips.r2

e asm.arch=mips
e asm.bits=32
e cfg.bigendian=true
e anal.limits=false

# Zignature matching thresholds (lower defaults so manual zo+z/ works)
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4

# Do NOT use bin.baddr on flat binaries — r2 ignores it for raw files.
# Instead, work at file offsets and add 0x80000000 mentally for VA.

# Type definitions
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/signal.h
to cobham/tt_cshell.h

# Known function addresses (file offsets, NOT virtual addresses):
# Authentication / User DB
f fcn.userdb_auth 0x280 @ 0x6dd3c
f fcn.userdb_init_default_creds 0x100 @ 0x6df1c
f fcn.password_change 0x1c0 @ 0x6e00c
f fcn.admin_reset_rsa 0x1c0 @ 0x6dabc
f fcn.telnet_input_reader 0x100 @ 0x6d098
f fcn.telnet_auth_prompt 0x300 @ 0x6d340

# Lua C bindings (called from Lua web UI)
f fcn.lua_check_password 0x100 @ 0x1df278
f fcn.lua_change_password 0x80 @ 0x1df428

# Crypto
f fcn.sha1_init 0x40 @ 0x1b047c
f fcn.sha1_update 0x40 @ 0x1b04b8
f fcn.sha1_final 0x40 @ 0x1b05ec

# String comparison
f fcn.strcmp 0x40 @ 0x5b638c
f fcn.memcmp 0x40 @ 0x5b6048
f fcn.strlen 0x40 @ 0x5b65d0

# Key data structures
f str.sha1 1 @ 0x631200
f str.admin 1 @ 0x631210
f str.default_password_1234 1 @ 0x631218
f str.root 1 @ 0x631220
f str.userdb_lock 1 @ 0x631228
f data.rsa_pubkey 0x8c @ 0x631174
f data.userdb_struct 0x1a4 @ 0x817b60
