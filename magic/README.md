# Magic Signatures

Custom radare2 magic files for firmware identification. These supplement r2's
built-in magic with vendor-specific and protocol-specific patterns.

## Usage

```r2
# Scan current binary for all firmware formats
/m ~/.local/share/radare2/magic/firmware.magic

# Scan for crypto constants (find AES, CRC tables in .data)
/m ~/.local/share/radare2/magic/crypto_tables.magic

# Scan for protocol handler strings (find HTTP, MQTT, RTSP, gRPC handlers)
/m ~/.local/share/radare2/magic/proto_fingerprint.magic

# Load a vendor-specific file for deeper identification
/m ~/.local/share/radare2/magic/cisco_ios.magic
/m ~/.local/share/radare2/magic/icom_firmware.magic
```

## Files

| File | Purpose | Formats Covered |
|------|---------|-----------------|
| `firmware.magic` | **Universal catch-all** — load this first | DJI, Rockchip, TRX, SEAMA, Netgear, D-Link, JBOOT, LZ4, SquashFS LZMA, Cisco IOS (stub), Icom (stubs), VxWorks (stub), Juniper (stub) |
| `bosch_cppenc.magic` | Bosch VIP-X CPP-ENC container | Proprietary ROMFS flat image — use with `r2 -n` (raw mode) |
| `cisco_ios.magic` | Cisco IOS ELF identification | IOS monolithic ELF (MIPS/PPC), self-extracting ZIP wrapper, IOS-XE, ROMMON, c1700 FEEDFACE+ZIP |
| `cobham_bgan.magic` | Cobham SATCOM / Thrane & Thrane | TIIF container, BGAN .dl archive, MAIN_CPU image, eCos ARM flat binary |
| `crypto_tables.magic` | Cryptographic algorithm tables | CRC-8, CRC-16, CRC-32, CRC-32C, AES S-boxes, SHA-256/SHA-1 constants, MD5 T-table, Blowfish, DES, ChaCha20, RC4 |
| `icom_firmware.magic` | Icom radio firmware containers | IC-905 DAT (AES), IC-705 DAT (AES), IC-R8600 DAT (LZSS), DU3 (AES), FIRM/AP-90M (VxWorks) |
| `juniper_junos.magic` | Juniper JunOS firmware | 55AA block-compressed ISO, domestic package ELF (/red/herring interpreter), package metadata, metatags |
| `proto_fingerprint.magic` | Protocol handler fingerprinting | DJI DUPC, HTTP, SNMP, MQTT, Modbus, Telnet, FTP, SSH/Dropbear, CoAP, LwM2M, TR-069, UPnP/SSDP, SIP, RTSP, IKEv2/IPsec, RADIUS, Diameter, SpaceX gRPC/BwpProxy |
| `silabs_gbl.magic` | Silicon Labs Gecko Bootloader | GBL plaintext/encrypted images, application/bootloader/SE segments, ECDSA signature, D-Link Z-Wave OTA, Realtek Ameba Z-II |
| `starlink.magic` | SpaceX Starlink firmware | sxverity container, gRPC binary fingerprints (SpaceX.API.Device), UserClass enum, Slate key-value store, BwpProxy command bus, UnlockService, STSafe HSM |
| `uefi.magic` | UEFI / EDK2 firmware | EFI PE32+ executables, Firmware Volumes (FV/FFS), capsule updates, NvRam variable store, Intel Flash Descriptor, ME firmware, ACPI tables, Secure Boot databases |
| `vxworks.magic` | VxWorks kernel images | VxWorks 7 kernel ELF (x86-64, ARM32, AArch64), DKM relocatable, .wrs_build_vars metadata, v5/v6 version banner, ROMFS, Wind River TFTP boot (.vxz) |

## Strategy: One File vs Many

**Quick triage (unknown blob):**
```r2
/m ~/.local/share/radare2/magic/firmware.magic
```
Catches ~80% of cases with one command. The `firmware.magic` file includes brief
stubs for all major formats; vendor-specific files add depth.

**Deep dive (known vendor):**
```r2
/m ~/.local/share/radare2/magic/cisco_ios.magic   # IOS version strings, inner/wrapper
/m ~/.local/share/radare2/magic/starlink.magic    # SpaceX binary fingerprints
/m ~/.local/share/radare2/magic/proto_fingerprint.magic  # Protocol attack surface
```

**Crypto/algorithm hunting (stripped binary):**
```r2
/m ~/.local/share/radare2/magic/crypto_tables.magic
# Then cross-reference to find callers:
axt @ hit0_0
```

## Notes

- `firmware.magic` deliberately includes brief stubs for Icom, Cisco, VxWorks,
  and Juniper formats so a single scan catches them. The vendor-specific files
  add version strings, sub-type discrimination, and deeper field extraction.
- `proto_fingerprint.magic` works best on **mapped binaries** (after analysis):
  use `/m` at any seek position to find protocol handler strings in the current
  binary's address space.
- `crypto_tables.magic` is designed for **unmapped flat images** as well as
  loaded binaries; the byte sequences are unique enough to produce few false
  positives.
- **Raw vs ELF mode**: r2's `/m` scans the file as r2 sees it in memory.
  For ELF/PE binaries, r2 maps only loadable segments — so magic patterns that
  look for strings deep in an ELF (e.g. `.symtab`, `.wrs_build_vars`) may not
  fire. For raw firmware blobs (flat binary, ROM images, containers), open with
  `r2 -n` (no analysis) so the full file is mapped at offset 0:
  ```r2
  r2 -n -q firmware.bin
  /m ~/.local/share/radare2/magic/vxworks.magic    # fires on raw blobs
  /m ~/.local/share/radare2/magic/bosch_cppenc.magic
  ```
  For ELF analysis, use `is~wrs_kernel` or string searches instead of `/m`
  for symbols that are in the ELF section headers or symbol tables.
- `bosch_cppenc.magic` requires `-n` (raw mode) because Bosch VIP-X containers
  are proprietary ROMFS images, not ELFs. Use `r2 -n vip_x.app1`.
