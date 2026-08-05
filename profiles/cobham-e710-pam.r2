# r2 profile: Cobham BGAN Explorer 710 — pam_thrane.so (ARM LE, Linux)
# ELF shared object, r2 handles base address automatically.
#
# Usage: r2 -i profiles/cobham-e710-pam.r2 pam_thrane.so

e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# Key functions
f sym.pam_authenticate 0x3c8 @ 0x42f8
f sym.check_root_password 0x54 @ 0x4920
f sym.check_oem_password 0x50 @ 0x4874
f sym.check_cert_password 0x54 @ 0x48c8
f sym.check_password_rsa 0x15c @ 0x4700

# Embedded RSA public keys (extracted from .rodata)
f data.oem_rsa_1024_pubkey 0xa2 @ 0x19f50
f data.cert_rsa_1024_pubkey 0xa2 @ 0x19ff4
f data.root_rsa_key_blob 0x8c @ 0x1a090

# Crypto functions (statically linked LibTomCrypt)
f sym.md5_init 0x24 @ 0x53e0
f sym.md5_append 0x108 @ 0x5418
f sym.md5_finish 0xac @ 0x5520
f sym.sha1_init 0x50 @ 0xf0c0
f sym.rsa_import 0x408 @ 0x18ae4
f sym.rsa_verify_hash_ex 0x34c @ 0x19648

# Key strings
f str.root 4 @ 0x19f0c
f str.cert 4 @ 0x19f14
f str.password_prompt 10 @ 0x19f2c
f str.key_format 7 @ 0x19f24
