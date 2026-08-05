# dji-assistant-win32.r2 — DJI Assistant 2 Windows PE32 service DLL profile
# Covers: DJIService.exe, DJIDevice.dll, DJIUavService.dll,
#         DJIRcService.dll, DJIGlsService.dll
#
# Blob: 19fd03841a0e07ecf041b45832f776f7d9630184a8eecf063ff0812b3320c2bc
# Discovered: 2026-05-06
#
# Key findings embedded:
#   app_name = "dji_assistant" (register_device API)
#   sign key = "QfWWouvQn5TnDO" (HMAC-SHA1, decrypted from obfuscated blob)
#   DJIService.exe .dji2 section (16MB, entropy 7.85) = custom-packed payload
#     - EP at section offset 0xdcbf41, obfuscated x86
#     - IAT pre-resolved by loader; LoadLibraryA+GetProcAddress in imports
#     - Decryptor stub at section offset 0xD80000 (entropy 6.82)

# Architecture
e asm.arch=x86
e asm.bits=32
e cfg.bigendian=false

# PE analysis settings
e bin.demangle=true
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.strings=true

# C++ demangling for Qt5/MSVC mangled names
e bin.demangle=true
e asm.demangle=true

# Zignature settings
e zign.graph=true
e zign.refs=true
e zign.min=16
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4

# Load DJI Windows type definitions
e dir.types=~/.local/share/radare2/types
to dji/dji-assistant-win32.h

# Load Windows base types (structs, functions)
to windows/structs.h
to windows/functions.h

# Load named function signatures (DJIDevice.dll + DJIUavService.dll)
zo dji/DJIDevice.zsig
zo dji/DJIUavService.zsig

# Load VC++ runtime signatures (DJI Assistant 2 uses VS2019/VS2022)
zo windows/x86/vs2019-vcruntime140.zsig
zo windows/x86/vs2022-vcruntime140.zsig
zo windows/x86/vs2022-msvcp140.zsig

# Useful flags for DJIUavService.dll analysis
# (VA-relative — seek to binary base first if ImageBase != 0x10000000)
# f dji.register_device_builder @ 0x10276d80
# f dji.hmac_key_decrypt_loop   @ 0x10276f30
# f dji.pack_list_xml_parser    @ 0x103c6130
# f dji.dji_assistant_xml_check @ 0x103c627f

# Visual
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
