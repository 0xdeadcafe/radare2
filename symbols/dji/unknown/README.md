# symbols/dji/unknown/ — INTENTIONALLY EMPTY PLACEHOLDER

This directory exists to hold `.r2` symbol scripts for DJI firmware modules
whose binary hash is not yet known (cannot be grouped under a specific product).

**When to use:**
- New DJI binary is confirmed but product family/version not yet catalogued
- Interim analysis before the binary is assigned to a sub-directory

**Current status:** No unknown DJI binaries pending. All known DJI symbols are
filed under their specific module type:
- `symbols/dji/flyc/` — Flight controller m0306
- `symbols/dji/gimbal/` — Gimbal controller
- `symbols/dji/amba_sys/` — Ambarella camera system
- `symbols/dji/encode_usb/` — TI DaVinci video encoder
- `symbols/dji/lightbridge/` — Lightbridge / OFDM
- `symbols/dji/ofdm/` — OFDM module
- `symbols/dji/wifi/` — Wi-Fi module (m0700, m2700)
- `symbols/dji/misc/` — Miscellaneous DJI binaries
