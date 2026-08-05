# DJI Fly Android ARM64 — r2 profile
# Covers: libsdk_base.so, libsdk_jni.so, libwaes.so  (DJI Fly 1.21.2)
# Discovered: 2026-05-06  Binary hash prefix: 995e7d6f (base), 03b113dc (jni)
#
# Load sequence:
#   r2_open(path, init_cmds="e asm.arch=arm;e asm.bits=64;e analysis.timeout=60;aa")
#   r2_cmd(sid, ". ~/.local/share/radare2/profiles/dji-fly-android-arm64.r2")

e asm.arch=arm
e asm.bits=64
e cfg.bigendian=false

# Type definitions
e dir.types=~/.local/share/radare2/types
to dji/dji-fly-android-arm64.h

# Zignatures — match against these binaries
# Zignature matching thresholds
e zign.graph=true
e zign.refs=true
e zign.mincc=1
e zign.minsz=4
zo dji/libsdk_base-fly121.zsig
zo dji/libwaes-fly121.zsig
z

# Key function flags (libsdk_base.so addresses — base=0 PIE)
# Apply after opening libsdk_base.so:
# f WAES_decrypt_real @ 0x34ca90
# f mix_shift @ 0x34c3e8
# f uav_white_box_decrypt @ 0x34be60
# f get_key_chain_info @ 0x34bf68
# f GetWhiteBoxKeyChainString_whitebox @ 0x34bfd8
# f CreateSignatureWithSHA1 @ 0x2ed06c
# f keychain_table @ 0x6d8d38
# f WAES_table @ 0x7416a0
