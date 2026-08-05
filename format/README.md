# Format Definitions

Structure definitions for parsing firmware headers with r2's `pf` command.
Installed to `~/.local/share/radare2/format/` by `skel/install.sh`.

## Usage

```r2
# Load all format definitions
. ~/.local/share/radare2/format/firmware.pf

# Parse header at current offset
pf.uimage_header

# Parse at specific offset
pf.uimage_header @ 0x1000

# List all loaded formats
pf.
```

## Quick Triage Workflow

```r2
# 1. Identify the format via magic scan
/m ~/.local/share/radare2/magic/firmware.magic
s hit0_0

# 2. Load all formats
. ~/.local/share/radare2/format/firmware.pf

# 3. Parse the header
pf.uimage_header        # if U-Boot
pf.dji_imah_header      # if DJI IM*H
pf.dji_xv4_header       # if DJI xV4 container
pf.amba_part_header     # if Ambarella partition
```

## Available Formats

### Generic Firmware

| Format | Magic | Size | Description |
|--------|-------|------|-------------|
| `pf.uimage_header` | 0x27051956 | 64 B | U-Boot image header (big-endian) |
| `pf.trx_header` | "HDR0" | 28 B | Broadcom TRX firmware |
| `pf.seama_header` | 0x5EA3A417 | 16 B | SEAMA firmware |
| `pf.squashfs_super` | "hsqs"/"sqsh" | 96 B | SquashFS v4 superblock |
| `pf.ubi_ec_header` | "UBI#" | 64 B | UBI erase counter (big-endian) |
| `pf.jffs2_node` | 0x1985 | 12 B | JFFS2 node header |
| `pf.cpio_newc` | "070701" | 110 B | CPIO newc format (ASCII) |
| `pf.android_boot` | "ANDROID!" | ~1.6 KB | Android boot image v0 |

### DJI xV4 Container

| Format | Size | Description |
|--------|------|-------------|
| `pf.dji_xv4_header` | 64 B | xV4 package header (Phantom, Mavic, Spark, Inspire) |
| `pf.dji_xv4_entry` | 52 B | xV4 module entry (follows header, one per module) |

```r2
. ~/.local/share/radare2/format/firmware.pf
pf.dji_xv4_header @ 0
# Jump to first module entry (at header size offset)
pf.dji_xv4_entry @ 64
```

### DJI IM\*H Signed Module

| Format | Size | Description |
|--------|------|-------------|
| `pf.dji_imah_header` | 192 B | IM\*H module header (name, type, version, crypto params) |
| `pf.dji_imah_chunk` | 32 B | IM\*H chunk header (offset, size, flash address) |

```r2
pf.dji_imah_header @ 0
# Payload starts after header_size + signature_size
```

### Ambarella Camera Firmware

| Format | Size | Description |
|--------|------|-------------|
| `pf.amba_a9_header` | 40 B | Ambarella A9 main header (model, version, CRC) |
| `pf.amba_mod_entry` | 8 B | Ambarella module entry |
| `pf.amba_part_header` | 256 B | Ambarella partition header (magic at +24) |
| `pf.amba_romfs_header` | 2048 B | Ambarella ROMFS partition |
| `pf.amba_romfs_entry` | 128 B | Ambarella ROMFS file entry |

### DJI DUPC Protocol

| Format | Description |
|--------|-------------|
| `pf.dji_dupc55_hdr` | DUPC 0x55 packet header (4 B: magic + length_ver + hcrc) |
| `pf.dji_dupc55_full` | DUPC 0x55 full 13-byte header (src, dst, seq, cmd_type, cmd_set, cmd_id) |
| `pf.dji_wifi_cmd_exec` | DUPC EXEC_COMMAND frame (cmd_set=7, cmd_id=0x10) — RCE injection frame |
| `pf.dji_wifi_set_ssid` | DUPC SET_SSID frame |
| `pf.dji_wifi_set_password` | DUPC SET_PASSWORD frame |
| `pf.dji_dupcab_hdr` | DUPC 0xAB packet header |

### DJI Other

| Format | Description |
|--------|-------------|
| `pf.dji_mvfc_header` | Mavic FC encrypted container (41 B) |
| `pf.dji_flyc_param` | FlyC parameter table entry (hash + type + name) |
| `pf.dji_key_info` | DJI encryption key info block |

## Format String Syntax

| Char | Type | Size |
|------|------|------|
| `d` | dword | 4 B |
| `w` | word | 2 B |
| `b` | byte | 1 B |
| `q` | qword | 8 B |
| `z` | null-terminated string | variable |
| `[N]z` | fixed-length string | N B |
| `[N]d` | array of N dwords | 4N B |
| `e` | toggle endianness | — |
| `x` | hex dword | 4 B |

See `pf??` in r2 for the complete format specifier list.
