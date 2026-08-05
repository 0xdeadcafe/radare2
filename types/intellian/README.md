## Intellian iARM Type Definitions

Vendor-specific type definitions for Intellian iARM-GX / iARM-nx firmware.

### Files

| File | Contents | Populated by |
|---|---|---|
| `iarm_cgi_structs.h` | cJSON wrapper, bim_user_cfg, UIF message, NX JSON API request | manual + corpus_commit.py |

### Usage

These are loaded automatically by `profiles/intellian-arm-glibc.r2`:
```
to intellian/iarm_cgi_structs.h
```

Or manually in an r2 session:
```
to intellian/iarm_cgi_structs.h
```

### How to extend

After an analysis session that reveals new structs (via `pdg` in r2ghidra):
1. Add the new struct definition to `iarm_cgi_structs.h`
2. Run `skel/install.sh` to install to `~/.local/share/radare2/`
3. Run `corpus_commit.py` with the binary hash — it will merge session-discovered types

### Source binaries

- `nxagent.cgi` (iARM-nx v2.07, hash 55a7d93c…) — CGI dispatcher, cJSON structs
- `acu_server` (iARM-nx v2.02, hash 2228aacf…) — UIF protocol daemon
- `libcommon.so` — shared auth/escape library

### References

- `vault/Findings/CMD_INJECTION_55a7d93c_1.md`
- `vault/Findings/CMD_INJECTION_acu_server_2228aacf.md`
- `vault/Findings/CMD_INJECTION_preauth_libcommon_setagent.md`
