# DJI Type Definitions for radare2

Type definition headers for DJI firmware analysis.

## Files

| File | Contents |
|------|----------|
| `dji-common.h` | Enums: module types, encryption keys, DUPC commands, products |
| `dji-structs.h` | Structs: xV4, IM*H, DUPC, Ambarella headers |

## Usage

```r2
# Load type definitions
to types/dji/dji-common.h
to types/dji/dji-structs.h

# View loaded types
ts                          # List structs
te                          # List enums

# Apply struct to data
tp dji_imah_header @ 0      # Parse IM*H header at offset 0

# Look up enum values
te dji_module_kind          # Show module kind values
te dji_module_kind 3        # What is kind=3? (FLYC)
```

## With Profiles

Add to your profile (e.g., `profiles/dji-flyc.r2`):

```r2
# Load DJI types
to dji/dji-common.h
to dji/dji-structs.h
```

## Enum Reference

### Module Types

```
DJI_KIND_CAMERA = 1       (m01xx)
DJI_KIND_FLYC = 3         (m03xx)
DJI_KIND_GIMBAL = 4       (m04xx)
DJI_KIND_ENCODER = 8      (m08xx)
DJI_KIND_LIGHTBRIDGE = 9  (m09xx)
```

### Encryption Keys

```
DJI_ENC_PUEK  - Production Update Encryption Key
DJI_ENC_RIEK  - R&D Image Encryption Key
DJI_ENC_IAEK  - Inner Image Encryption Key
```

### DUPC Command Sets

```
DJI_CMDSET_GENERAL = 0
DJI_CMDSET_CAMERA = 2
DJI_CMDSET_FLYC = 3
DJI_CMDSET_GIMBAL = 4
```

## Struct Sizes

| Struct | Size | Magic |
|--------|------|-------|
| `dji_xv4_header` | 64 bytes | 0x12345678 |
| `dji_xv4_entry` | 52 bytes | - |
| `dji_imah_header` | 192 bytes | "IM*H" |
| `dji_imah_chunk` | 32 bytes | - |
| `amba_part_header` | 256 bytes | 0xA324EB90 @ +24 |

## Notes

- Structs use basic C types (`int`, `char`, `short`, `long`) for r2 compatibility
- For precise binary parsing, use `pf` format strings in `format/firmware.pf`
- The `tp` command shows struct fields with values
- Combine with zsigs for full analysis workflow
