# DJI Firmware Format Analysis

Analysis of firmware formats from the `dji-tools` repository for magic signature and zsig generation.

## Firmware Hierarchy

```
DJI Firmware Package (.bin)
├── xV4 Container (main package)
│   ├── Module 0: IM*H signed module (.sig) or raw
│   │   ├── Ambarella firmware (camera)
│   │   │   ├── System Software partition
│   │   │   ├── DSP uCode partition
│   │   │   ├── ROM Data (ROMFS filesystem)
│   │   │   ├── Linux Kernel
│   │   │   └── Linux Root FS (UBIFS)
│   │   └── Other module types
│   ├── Module 1: Flight Controller
│   ├── Module 2: Gimbal
│   └── ... more modules
```

## 1. xV4 Container Format

**Source:** `dji_xv4_fwcon.py`

### Magic Pattern
- **Offset:** 0
- **Magic:** `0x12345678` (little-endian: `78 56 34 12`)
- **Version field:** at offset 4 (varies: 0x0000, 0x0001, 0x0002+)

### Header Structure (64 bytes)
```
Offset  Size  Field
0       4     magic (0x12345678)
4       2     magic_ver (format version: 0=2014, 1=2015-2017, 2+=2016+)
6       2     hdrend_offs (header end offset)
8       4     timestamp
12      16    manufacturer (string)
28      16    model (string)
44      2     entry_count (number of modules)
46      4     ver_latest_enc (XOR encoded)
50      4     ver_rollbk_enc (XOR encoded)
54      10    padding
```

### Module Entry Structure (48 bytes each)
```
Offset  Size  Field
0       1     target (module type, 5 bits kind + 3 bits model)
1       1     spcoding (encryption type in upper nibble)
2       2     reserved2
4       4     version
8       4     dt_offs (data offset)
12      4     stored_len
16      4     decrypted_len
20      16    stored_md5
36      16    decrypted_md5
```

### Module Types (target field)
| Kind | Name | Description |
|------|------|-------------|
| 1 | CAM | Camera (Ambarella) |
| 3 | MC | Main Controller (Flight Controller) |
| 4 | GIMBAL | Gimbal controller |
| 8 | VENC | Video encoder |
| 9 | LBMCA | Lightbridge MCU (air) |
| 12 | ESC | Electronic Speed Control |
| 14 | LBMCG | Lightbridge MCU (ground) |

### Encryption
- Type 1: AES-128-CBC
- Key: `96 70 9a D3 26 67 4A C3 82 B6 69 27 E6 d8 84 21`
- IV: all zeros

---

## 2. IM*H Signed Module Format

**Source:** `dji_imah_fwsig.py`

### Magic Pattern
- **Offset:** 0
- **Magic:** `IM*H` (ASCII: `49 4D 2A 48`)

### Header Structure (192 bytes)
```
Offset  Size  Field
0       4     magic ("IM*H")
4       4     header_version (0=2016, 1=2017, 2=2018)
8       4     size
12      4     reserved
16      4     header_size
20      4     signature_size (RSA signature length)
24      4     payload_size
28      4     target_size
32      1     os
33      1     arch
34      1     compression
35      1     anti_version
36      4     auth_alg
40      4     auth_key (4-char identifier like "PRAK")
44      4     enc_key (4-char identifier like "PUEK")
48      16    scram_key (encrypted scramble key)
64      32    name (module name string)
96      4     type (module type identifier)
100     4     version
104     4     date
108     4     encr_cksum
112     16    reserved2
128     16    userdata
144     8     entry
152     4     plain_cksum
156     4     chunk_num
160     32    payload_digest (SHA256)
```

### Chunk Header (32 bytes each, follows main header)
```
Offset  Size  Field
0       4     id (4-char chunk ID)
4       4     offset
8       4     size
12      4     attrib
16      8     address
24      8     reserved
```

### Common Key Identifiers
- **Auth keys:** PRAK, RRAK, GFAK, SLAK
- **Enc keys:** PUEK, RIEK, RREK, TBIE, UFIE, TRIE, TKIE

---

## 3. Ambarella Firmware Format

**Source:** `amba_fwpak.py`

### Magic Pattern
- No fixed magic at offset 0
- **Identification:** Look for "Amba" strings or model name at offset 0
- Model name is 32-byte null-padded string

### Main Header Structure (40 bytes + variable)
```
Offset  Size  Field
0       32    model_name (string, identifies device)
32      4     ver_info
36      4     crc32
```

### Partition Header Structure (256 bytes)
```
Offset  Size  Field
0       4     crc32
4       4     version
8       4     build_date
12      4     dt_len (data length)
16      4     mem_addr
20      4     flag1
24      4     magic (0xA324EB90)
28      4     flag2
32      224   padding
```

### Partition Magic
- **Value:** `0xA324EB90` (little-endian: `90 EB 24 A3`)
- **Offset:** 24 bytes into partition header

### Partition Types
| Index | ID | Name |
|-------|-----|------|
| 0 | sys | System Software |
| 1 | dsp_fw | DSP uCode |
| 2 | rom_fw | System ROM Data (ROMFS) |
| 3 | lnx | Linux Kernel |
| 4 | rfs | Linux Root FS (UBIFS) |

---

## 4. ROMFS Filesystem Format

**Source:** `amba_romfs.py`

### Magic Pattern
- **Offset:** 4
- **Magic:** `0x66FC328A` (little-endian: `8A 32 FC 66`)

### Partition Header (2048 bytes)
```
Offset  Size  Field
0       4     file_count
4       4     magic (0x66FC328A)
8       2040  padding (filled with 0xFF)
```

### File Entry Structure (128 bytes each)
```
Offset  Size  Field
0       116   filename (null-terminated string)
116     4     offset
120     4     length
124     4     magic (0x2387AB76)
```

### File Entry Magic
- **Value:** `0x2387AB76` (little-endian: `76 AB 87 23`)
- Can be used for searching/recovery

---

## 5. UBIFS Format

### Magic Pattern
- **Magic:** `UBI#` at file start (ASCII: `55 42 49 23`)
- Standard UBIFS format, can be mounted with Linux tools

---

## Magic Signatures Summary

| Format | Magic | Offset | Hex Pattern |
|--------|-------|--------|-------------|
| xV4 Container | 0x12345678 | 0 | `78 56 34 12` |
| IM*H Module | "IM*H" | 0 | `49 4D 2A 48` |
| Ambarella Partition | 0xA324EB90 | 24* | `90 EB 24 A3` |
| ROMFS Header | 0x66FC328A | 4 | `8A 32 FC 66` |
| ROMFS File Entry | 0x2387AB76 | 124* | `76 AB 87 23` |
| UBIFS | "UBI#" | 0 | `55 42 49 23` |

*Offset within structure, not file

---

## Symbol Files Available

Located in `dji-tools/symbols/`:

### Flight Controller (m0306)
- `P3X_FW_V01.07.0060_m0306.map` - Phantom 3
- `wm100_0306_*.map` - Spark
- `wm220_0306_*.map` - Mavic Pro

### Lightbridge STM32 (m0900)
- `P3X_FW_V01.07.0060_m0900.map`
- `P3X_FW_V01.08.0080_m0900.map`

### Ambarella System Software
- `P3X_FW_V01.08.0080_m0100_part_sys.map`
- `wm161_0100_*.map` - Mini 2

### Gimbal Controllers
- `C1_FW_V01.05.0080_m1400.map` - Osmo
- `C1_FW_V01.06.0000_m1401.map`

---

## Recommended Magic Implementation

### For r2 magic file:
```
# DJI xV4 Firmware Container
0 lelong 0x12345678 DJI xV4 Firmware Package
>4 leshort x \b, version %d

# DJI IM*H Signed Module
0 string IM*H DJI IMaH Signed Firmware Module
>4 lelong x \b, header version %d

# Ambarella ROMFS
4 lelong 0x66FC328A Ambarella ROMFS Filesystem
>0 lelong x \b, %d files

# UBIFS
0 string UBI# UBIFS Filesystem Image
```

### For binwalk magic:
```python
# DJI signatures for binwalk
signatures = [
    {"offset": 0, "magic": b"\x78\x56\x34\x12", "description": "DJI xV4 firmware container"},
    {"offset": 0, "magic": b"IM*H", "description": "DJI IMaH signed module"},
    {"offset": 4, "magic": b"\x8A\x32\xFC\x66", "description": "Ambarella ROMFS filesystem"},
    {"offset": 0, "magic": b"UBI#", "description": "UBIFS filesystem"},
]
```
