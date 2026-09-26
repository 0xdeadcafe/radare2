# Juniper SRX Type Definitions

C headers for Juniper JunOS SRX analysed binaries. Load with `to juniper/<file>.h`.

## Usage

```r2
e dir.types=~/.local/share/radare2/types
to juniper/srx_httpd_gk.h
aaft
```

Or loaded automatically via the `juniper-srx.r2` profile.

## Files

| File | Source | Key Types |
|------|--------|-----------|
| `srx_httpd_gk.h` | HTTPD-GK (JunOS 21.3R1.9, blob 270d9123) | `dvpn_sa_entry_t`, `dvpn_token_entry_t` |

## `dvpn_sa_entry_t`

Discovered from HTTPD-GK — the DVPN security association entry struct.
Fields at confirmed offsets from the SA linked-list traversal:

| Offset | Field | Notes |
|--------|-------|-------|
| 0x00 | `ike_id[0xa8]` | IKE identifier string |
| 0xa8 | `sa_name[4]` | SA name passed to `system()` — **injection sink** |
| 0x3f0 | `ipsec_ip` | IPsec tunnel source IP |
| 0x3f8 | `ipsec_field_3f8` | Used in `system()` call |
| 0x41a | `flag_41a` | Branch flag in `delete_sa()` |

## `dvpn_token_entry_t`

DVPN token table entry for authenticated VPN clients:

| Field | Size | Notes |
|-------|------|-------|
| `username[64]` | 64 B | VPN username |
| `token[128]` | 128 B | Authentication token |
| `ike_id[64]` | 64 B | IKE identifier |
| `client_id[64]` | 64 B | Client identifier |
| `remote_ip[16]` | 16 B | Remote IP string |
| `config_name[64]` | 64 B | Config name |
| `ike_user_type` | 4 B | User type enum |
| `ref_count` | 4 B | Reference count |

## Vulnerability Reference

Finding: `vault/Findings/CMD_INJECTION_juniper_HTTPD-GK.md`  
Pattern: `vault/Patterns/CGI_UNVALIDATED_PASSTHROUGH.md`

The `sa_name` field at offset `0xa8` is passed directly to `system()` without
sanitisation when processing DVPN DELETE requests, enabling pre-auth RCE.
