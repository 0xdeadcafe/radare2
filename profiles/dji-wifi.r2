# dji-wifi.r2 — DJI Wi-Fi Module Vendor Profile
# For DJI Wi-Fi modules using the DUPC 0x55 protocol:
#   P3C/P3S/P3_4K m0700 (clisrv binary, uClibc 0.9.33.2 / MIPS32 BE)
#   m2700 (similar architecture)
#
# This profile is selected automatically when vendor slug = "dji" + arch = MIPS32.
# See: scripts/aether_r2profile.py _VENDOR_PROFILE_MAP ("mips","32","dji")
#
# Usage: r2 -i profiles/dji-wifi.r2 binary
#        Or from r2: . profiles/dji-wifi.r2

# ── Base MIPS32 BE + uClibc arch profile ─────────────────────────────────────
# Sets asm.arch=mips, bits=32, bigendian=true, loads libc types, handles PLT.
. /root/.local/share/radare2/profiles/linux-uclibc-mips.r2

# ── DJI-specific type definitions ────────────────────────────────────────────
# dji-common.h: DUPC command set enums (CMD_SET_GENERAL, CMD_SET_WIFI, ...)
# dji-structs.h: DUPC 0x55 packet structs (dji_dupc55_hdr, dji_wifi_cmd, ...)
e dir.types=~/.local/share/radare2/types
to dji/dji-common.h
to dji/dji-structs.h

# ── Firmware format struct definitions ────────────────────────────────────────
# pf.dji_dupc55_full — apply with: pf.dji_dupc55_full @ <recv_buf_addr>
. /root/.local/share/radare2/format/firmware.pf

# ── Protocol and crypto identification ────────────────────────────────────────
/m /root/.local/share/radare2/magic/proto_fingerprint.magic
/m /root/.local/share/radare2/magic/crypto_tables.magic

echo "DJI Wi-Fi (DUPC 0x55): types loaded. Use 'pf.dji_dupc55_full @ <buf>' to parse packets."
echo "CRC8 seed=0x77 poly=0x31, CRC16 seed=0x3692 poly=0x1021"
echo "Reference: skel/.local/share/radare2/docs/protocols/dji-dupc-0x55.md"
