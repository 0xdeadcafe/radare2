# DJI Firmware Module Types Reference

This document maps DJI firmware module type codes to their hardware targets.

## Module Target Encoding

In xV4 firmware packages, the `target` byte encodes:
- **Bits 0-4**: Kind (component type)
- **Bits 5-7**: Model (variant within kind)

```
target = (kind & 0x1F) | ((model & 0x07) << 5)
```

## Module Types by Kind

### Kind 1: Camera (m01xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m0100 | FC300X | Camera 'Ambarella A9SE' App |
| 1 | m0101 | CAMLDR | Camera 'Ambarella A9SE' Loader |
| 2 | m0102 | CAMBST | Camera BST |
| 4 | m0104 | CAMBCPU | Camera BCPU |
| 5 | m0105 | CAMLCPU | Camera LCPU |
| 6 | m0106 | ZQ7020 | Camera 'Xilinx Zynq 7020' |

### Kind 2: Mobile App (m02xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| - | m0200 | MBAPP | Mobile application |

### Kind 3: Main Controller / Flight Controller (m03xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 5 | m0305 | MCLDR | Main controller 'A3' loader |
| 6 | m0306 | MCAPP | Main controller 'A3' app |

**Chips**: STM32F4xx (Cortex-M4)

### Kind 4: Gimbal (m04xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m0400 | GIMBAL0 | Gimbal model 0 |

**Chips**: STM32F103 (Cortex-M3)

### Kind 5: Central Board (m05xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m0500 | CENTER0 | Central board model 0 |

### Kind 6: Remote Radio (m06xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| - | m0600 | RMRAD | Remote radio controller |

### Kind 7: Wi-Fi (m07xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m0700 | WIFI0 | Wi-Fi module model 0 |

### Kind 8: Video Encoder in Air (m08xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m0800 | DM368 | Video encoder 'TI DaVinci DM368 Linux' |
| 1 | m0801 | IG810LB2 | Video encoder 'IG810 LB2_ENC' |

**Chips**: TI DaVinci DM365/DM368 (ARM926EJ-S)

### Kind 9: Lightbridge MCU in Air (m09xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m0900 | MCA1765 | Lightbridge MCU 'STM32F103' |

**Chips**: STM32F103 (Cortex-M3)

### Kind 10: Battery Firmware (m10xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| - | m1000 | BATTFW | Battery firmware |

### Kind 11: Battery Controller (m11xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m1100 | BATTERY | Battery controller 1 app |
| 1 | m1101 | BATTERY2 | Battery controller 2 app |

### Kind 12: ESC - Electronic Speed Control (m12xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m1200 | ESC0 | ESC motor 0 |
| 1 | m1201 | ESC1 | ESC motor 1 |
| 2 | m1202 | ESC2 | ESC motor 2 |
| 3 | m1203 | ESC3 | ESC motor 3 |

### Kind 13: Video Decoder (m13xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m1300 | DM365M0 | Video decoder 'TI DaVinci DM365 Linux' |
| 1 | m1301 | DM365M1 | Video decoder 'TI DaVinci DM385 Linux' |

### Kind 14: Lightbridge MCU on Ground (m14xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m1400 | MCG1765A | Lightbridge MCU 'LPC1765 GROUND LB2' |

**Chips**: NXP LPC1765 (Cortex-M3)

### Kind 15: Transmitter USB Controller (m15xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m1500 | TX68013 | Transmitter USB 'IG810 LB2_68013_TX' |

**Chips**: Cypress EZ-USB FX2 (8051)

### Kind 16: Receiver USB Controller Ground (m16xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m1600 | RX68013 | Receiver USB 'IG810 LB2_68013_RX ground' (GL300a) |
| 1 | m1601 | RXCY2014 | Receiver USB 'IG810 LB2_CY2014_RX ground' (GL300b+) |

### Kind 17: Visual Positioning / MVO (m17xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m1700 | MVOMC4 | Visual positioning module 'camera' |
| 1 | m1701 | MVOMS0 | Visual positioning module 'sonar' |

### Kind 19: Lightbridge FPGA in Air (m19xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m1900 | FPGAA0 | Lightbridge FPGA on air model 0 |

### Kind 20: Lightbridge FPGA on Ground (m20xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 3 | m2003 | FPGAG3 | Lightbridge FPGA on ground 'LB2' |

### Kind 25: IMU - Inertial Measurement Unit (m25xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m2500 | IMUA3M0 | IMU part 0 |
| 1 | m2501 | IMUA3M1 | IMU part 1 |

### Kind 26: RTK - Real Time Kinematic (m26xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 6 | m2606 | RTKAPP | RTK Application |
| 7 | m2607 | RTKLDR | RTK Loader |

### Kind 27: Wi-Fi Ground (m27xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| - | m2700 | WIFIGND | Wi-Fi ground module |

### Kind 29: PMU - Power Management Unit (m29xx)
| Model | Code | Name | Description |
|-------|------|------|-------------|
| 0 | m2900 | PMUA3LDR | PMU Loader |
| 1 | m2901 | PMUA3APP | PMU Application |

## Architecture Reference

| Module Types | Architecture | CPU | Notes |
|--------------|--------------|-----|-------|
| m0100-m0106 | ARM (A9) | Ambarella A9SE | Camera processor, runs Linux |
| m0305-m0306 | ARM (M4) | STM32F4xx | Flight controller |
| m0400 | ARM (M3) | STM32F103 | Gimbal controller |
| m0800 | ARM9 | TI DM368 | Video encoder, Linux |
| m0900 | ARM (M3) | STM32F103 | Lightbridge air MCU |
| m1300-m1301 | ARM9 | TI DM365/385 | Video decoder, Linux |
| m1400-m1401 | ARM (M3) | LPC1765 | Lightbridge ground MCU |
| m1500-m1601 | 8051 | Cypress FX2 | USB controllers |

## Encryption Key Types

DJI uses various encryption keys identified by 4-character codes:

| Key ID | Full Name | Usage |
|--------|-----------|-------|
| PUEK | Programming Update Encryption Key | Main firmware encryption |
| RIEK | R&D Image Encryption Key | Development/engineering builds |
| IAEK | Inner Image Encryption Key | Inner image encryption (m0801) |
| TRIE | TR Image Encryption | TrustZone images |
| TKIE | Trusted Kernel Image Encryption | Kernel/DTB encryption |
| TBIE | Trusted Boot Image Encryption | Boot image encryption |
| UFIE | Update Firmware Image Encryption | Update packages |

## Product Code Prefixes

| Prefix | Product |
|--------|---------|
| P3X | Phantom 3 Pro/Advanced |
| P3S | Phantom 3 Standard |
| P4 | Phantom 4 |
| WM100 | Spark |
| WM220 | Mavic Pro |
| WM230 | Mavic Air |
| WM240 | Mavic 2 |
| C1 | Lightbridge 2 |
| A3 | A3 Flight Controller |
| N3 | N3 Flight Controller |
| GL300 | Ground station remote |

## References

- dji-tools: https://github.com/o-gs/dji-firmware-tools
- DJI firmware research: https://dji.retroroms.info/
