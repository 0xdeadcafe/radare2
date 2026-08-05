# SpaceX Starlink Type Definitions

C headers for SpaceX Starlink user terminal firmware analysis. Load with `to spacex/<file>.h`.

## Usage

```r2
e dir.types=~/.local/share/radare2/types
to spacex/starlink.h
aaft

# Look up UserClass values
te starlink_user_class 0    # UNSET
te starlink_user_class 10   # OPERATOR
te starlink_user_class 20   # GOD_USER
```

Or loaded automatically via the `spacex-starlink-musl-arm64.r2` profile.

## Files

| File | Platform | Key Types |
|------|----------|-----------|
| `starlink.h` | AArch64 LE musl (catson/catapult, 2026.03.xx) | `sxverity_header`, `UserClass` enum, `BwpProxy` command/response structs, `SlateEntry`, gRPC dispatch types |

## Key Types

### `starlink_user_class` enum

Authentication/authorization tier for gRPC RPC gates:

| Value | Name | Access |
|-------|------|--------|
| 0 | `STARLINK_USER_UNSET` | No auth |
| 1 | `STARLINK_USER_CUSTOMER` | End-user API |
| 10 | `STARLINK_USER_OPERATOR` | Operator-level (field technician) |
| 20 | `STARLINK_USER_GOD_USER` | Full admin — bypasses all gates |

### `sxverity_header`

SpaceX custom Merkle-hash integrity container format (similar to dm-verity but file-level). Located at offset 0 in `.swu` firmware images.

### `bwp_command_t` / `bwp_response_t`

BwpProxy WebSocket command bus structures used by `emc_web_socket_server`. These carry unauthenticated commands via the LAN WebSocket interface on port `:8065`.

## Vulnerability References

| Finding | Class | Binary |
|---------|-------|--------|
| `AUTH_BYPASS_fd54cbdb_emc_ws_zero_auth.md` | Auth Bypass | `emc_web_socket_server` |
| `STARLINK-MMUT-GOD-USER-KEY-DISCLOSURE-2026.md` | Credential Disclosure | `user_mmut.project.so` |
| `STARLINK-UNLOCK-SSH-INJECTION-2026.md` | Command Injection | unlock service |
| `STARLINK-FRONTEND-LAN-RF-DISABLE-2026.md` | DoS / RF Disable | `user_terminal_frontend` |

Profile: `profiles/spacex-starlink-musl-arm64.r2`  
Magic: `magic/starlink.magic`
