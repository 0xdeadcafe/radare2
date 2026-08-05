# Type Definitions

C headers for structs, enums, and function signatures. Load in r2 with `to <file>`.

## Quick Reference

```r2
# Load types (base path = ~/.local/share/radare2/types when dir.types is set)
to libc/functions.h          # POSIX/libc function signatures
to libc/socket.h             # AF_*, SOCK_*, sockaddr structs
to libc/fcntl.h              # O_*, PROT_*, MAP_*, stat, dirent
to libc/errno.h              # linux_errno enum (te linux_errno 13 → EACCES)
to libc/signal.h             # linux_signal enum (te linux_signal 9 → SIGKILL)

# Apply to imports automatically after loading
aaft

# Look up enum value
te linux_errno 13            # EACCES
te linux_open_flags 2        # O_RDWR
te linux_signal 11           # SIGSEGV

# Show struct layout
ts sockaddr_in
ts stat

# Print struct at address
tp sockaddr_in @ 0x1234
```

## Directories

### Common Platform Types

| Directory | Contents | Load With |
|-----------|---------|-----------|
| `libc/` | POSIX types: functions, errno, signal, socket, fcntl/stat | `to libc/functions.h` etc. |
| `musl/` | musl libc internals + zsig-name variants | `to musl/functions.h` then `to musl/functions-zsig.h` |
| `openssl/` | libssl, libcrypto structs and function signatures | `to openssl/ssl.h` |
| `zlib/` | zlib stream and format types | `to zlib/zlib.h` |
| `ffmpeg/` | libavcodec, libavformat, libavutil | `to ffmpeg/avcodec.h` etc. |
| `vxworks/` | VxWorks 7 RTOS: task, semaphore, socket, errno | `to vxworks/vxworks.h` |

### Android / Mobile

| Directory | Contents |
|-----------|---------|
| `android/` | JNI types, bionic libc, Android logging (logcat), asset manager |

### Windows

| Directory | Contents |
|-----------|---------|
| `windows/` | Win32 API functions, structs (`SYSTEM_INFO`, `PROCESS_INFORMATION`, etc.), NTSTATUS codes, WinError codes, VC++ runtime function signatures, zsig-name variants |

### Embedded / Device Vendors

| Directory | Target | Key Types |
|-----------|--------|-----------|
| `cobham/` | Cobham SATCOM / Thrane & Thrane (SAILOR GX, Explorer 710) | `tt_cshell_cmd` dispatch table, `libfdloop` session, ACU message structs |
| `dji/` | DJI drone firmware (FlyC, Ambarella, Android SDK) | DUPC protocol frames, flight controller params, IM\*H header, encrypt key blocks |
| `intellian/` | Intellian iARM-GX / iARM-nx (JRC JUE-100GX, Viasat GX) | cJSON dispatch wrappers, UIF protocol, `bim_user_cfg`, `libcommon.so` structs |
| `juniper/` | Juniper SRX (JunOS) | `dvpn_sa_entry_t`, `dvpn_token_entry_t` — DVPN token table (HTTPD-GK analysis) — see `juniper/README.md` |
| `supermicro/` | Supermicro BMC (B2SC1-CPU) | `tag_dispatch_entry`, IPMI session struct, CGI env getters, `cgiGetPostVariable` |
| `spacex/` | SpaceX Starlink (catson/catapult) | `UserClass` enum, BwpProxy command types, unlock service key structs — see `spacex/README.md` |
| `embedded/arm-none-eabi/` | Cortex-M (newlib libc) | **Not present yet in `types/`; see note below** |

## Usage Patterns

### Firmware Analysis (musl/uclibc)

```r2
# musl: load both canonical and zsig-variant names so aaft covers both
to musl/functions.h
to musl/functions-zsig.h
aaft

# After zsig matching, functions named __malloc_usable_size get the right type
# because functions-zsig.h defines the underscore-prefixed variant
```

### Windows PE Analysis

```r2
to windows/functions.h      # Win32 API: CreateFile, VirtualAlloc, etc.
to windows/structs.h        # SYSTEM_INFO, CONTEXT, LIST_ENTRY, etc.
to windows/ntstatus.h       # NTSTATUS codes (0xC000xxxx)
to windows/winerror.h       # Win32 error codes (GetLastError values)
to windows/functions-zsig.h # zsig name variants for vcruntime functions
aaft
```

### VxWorks Analysis

```r2
# VxWorks-specific kernel services + POSIX compat layer
to vxworks/vxworks.h
aaft

# Look up task state
te vx_task_state 0x04       # SUSPEND
te vx_sem_opts 0x08         # SEM_INVERSION_SAFE
```

### DJI Firmware Analysis

```r2
# DJI structs (DUPC frames, IM*H header, FlyC params)
to dji/dji-structs.h

# DJI common types (protocol constants, module types)
to dji/dji-common.h

# Android SDK types (for DJI app analysis)
to android/jni.h
to dji/dji-fly-android-arm64.h
```

### CGI / Web Attack Surface

```r2
# Supermicro BMC ipmi.cgi
to supermicro/bmc_structs.h
# Then find the dispatch table:
afl~tag_dispatch,handler

# Intellian nxagent.cgi / acu_server
to intellian/iarm_cgi_structs.h
to libc/functions.h
aaft
```

## Zsig Name Variants

After zsig matching, function names may differ from their canonical form
(e.g., `__malloc_usable_size` instead of `malloc_usable_size`). The
`functions-zsig.h` files in `musl/` and `windows/` contain the
underscore-prefixed variants so `aaft` can apply types to zsig-matched
functions as well as imports.

Load **both** files before running `aaft`:

```r2
to musl/functions.h
to musl/functions-zsig.h
aaft
```

## Notes: `embedded/arm-none-eabi/`

There is currently **no** `types/embedded/arm-none-eabi/` directory in this
corpus. Type headers for Cortex-M newlib functions are **not yet generated** —
previous extraction produced `void f(void)` for all signatures (DWARF parameter
types were lost during extraction). Loading broken headers is worse than
nothing.

The corresponding zsig files in `zigns/embedded/arm-none-eabi/` **are correct**
and useful for function identification via `zo` + `z/`.

To regenerate, compile newlib with `-g` and use `tool/generate-zsig.py --types`:
```bash
./tool/generate-zsig.py --lib path/to/debug/libc.a --types -o newlib-v7em-types.h
```
