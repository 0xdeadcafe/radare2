# Icom AP-90M VxWorks 6.9 — MIPS32 Big-Endian flat binary
# Discovered 2026-05-21 from 8fbb6d21 (AP-90M v2 fw30.11)
# Container: FIRM magic (52-byte header) + ELF decompressor stub at 0x86800000
# Decompressed kernel loads at 0x80000000 (MIPS KSEG0)
#
# Key addresses:
#   Entry (reset vector): 0x80000000
#   Kernel init (jal target): 0x80423208
#   GP register: 0x80E036D0 (BSS/.sdata, 90KB past file end)
#   Stack pointer init: 0x80010000
#   SSH DSA host key (file offset): 0x737f6c
#   SSH RSA host key (file offset): 0x738110
#   RSAP2 TLS cert (file offset):   0x73cb14
#   RSAP2 TLS key (file offset):    0x73ce48
#   IKE cert (file offset):         0x87230e (VA 0x8087230e)
#   IKE private key (file offset):  0x8727ce (VA 0x808727ce)

e asm.arch=mips
e asm.bits=32
e cfg.bigendian=true
e anal.limits=false

# Zignature matching thresholds (lower defaults so manual zo+z/ works)
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4
# Rebase flat binary to 0x80000000
omr 0 0x80000000
# Types
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/signal.h
to vxworks/vxworks.h
