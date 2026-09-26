# DJI Firmware Symbols

r2 scripts containing symbol definitions for DJI drone firmware.

## Usage

Apply symbols when loading firmware in radare2:

```bash
r2 -i symbols/dji/flyc/P3X_V01.07.0060.r2 firmware.bin
```

Or load after opening:

```
[0x00000000]> . symbols/dji/flyc/P3X_V01.07.0060.r2
[0x00000000]> f~dji_flyc
```

## Important Notes

These are **address-based** symbol definitions, not pattern-matching signatures.
They only work when:

1. The firmware version matches exactly
2. The binary is loaded at the correct base address

For the flight controller (m0306), typical base addresses:
- P3X: `0x08020000` (STM32 flash)
- Mavic/Spark: `0x00420000`

Load with correct base:
```bash
r2 -m 0x08020000 firmware.bin
```

## Directory Structure

```
symbols/dji/
├── flyc/           # Flight controller (m0306)
├── lightbridge/    # Lightbridge STM32 (m0900)
├── amba_sys/       # Ambarella system (m0100)
├── gimbal/         # Gimbal controller (m1400/m1401)
├── ofdm/           # OFDM modem (m1300)
├── encode_usb/     # DM3xx encoder (m0800)
└── misc/           # Other modules
```

## Generating Byte-Pattern Signatures

If you have both the .map file AND matching firmware binary, you can
generate true zignatures that work across similar firmware versions:

```bash
# 1. Load firmware with symbols
r2 -i symbols/dji/flyc/P3X_V01.07.0060.r2 -m 0x08020000 P3X_flyc.bin

# 2. Analyze and generate signatures
[0x08020000]> aaa
[0x08020000]> e zign.prefix=dji_flyc
[0x08020000]> zg
[0x08020000]> zos P3X_flyc.zsig
```

The resulting .zsig contains byte patterns that can match functions
even in different firmware versions.

## Sources

Symbol maps from [dji-firmware-tools](https://github.com/o-gs/dji-firmware-tools).

Firmware can be obtained from:
- DJI official downloads (older versions)
- Extracted from update packages using dji-firmware-tools
