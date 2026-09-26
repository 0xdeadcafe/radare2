# r2 profile: Cobham BGAN Explorer 710 — ap_json_api (ARM LE, Linux)
# ELF executable, dynamically linked.
#
# Usage: r2 -i profiles/cobham-e710-api.r2 ap_json_api

e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false

# Authentication
f method.AuthHandler.authenticate 0x52c @ 0x4e888
f method.AuthHandler.execLoginHook 0x9c @ 0x4f1dc
f method.AuthHandler.execLogoutHook 0x9c @ 0x4f4a4
f method.AuthController.authenticate 0x468 @ 0x4fb20
f method.AuthController.execLoginHook 0x9c @ 0x50308
f method.AuthController.execLogoutHook 0x9c @ 0x50660

# Access control
f method.AccessMap.mayRead 0x160 @ 0x4b590

# File handling
f method.FileHandler.handleRequest 0x1e8 @ 0x4e620
f method.FileHandler.tryFile 0x1c0 @ 0x4e460
f method.FileHandler.fileUpload 0x2bc @ 0x4e078
f sym.normalizeString 0x6c @ 0x4c518

# Dangerous imports
f sym.imp.system 0xc @ 0x48be0
f sym.imp.popen 0xc @ 0x486c4
