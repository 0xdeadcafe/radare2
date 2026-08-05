# types/freebsd/ — FreeBSD / BSD userland type definitions

Type definitions for FreeBSD 12.x–14.x applicable to:
- **Juniper JunOS** (FreeBSD-based, MIPS64 and x86-64)
- **pfSense / OPNsense** (FreeBSD-based firewall distributions)
- **TrueNAS** (FreeBSD-based NAS OS)
- Any ELF binary with `/libexec/ld-elf.so.1` interpreter

## Usage

```r2
to freebsd/freebsd.h
tf kqueue               # kqueue event loop creation
tf kevent               # wait on events
tsc kevent              # show kevent struct layout
te bsd_so_opt           # BSD socket option constants
te kevent_filter        # kqueue filter identifiers
te kevent_flags         # kqueue action/status flags
te bsd_errno_ext        # BSD-specific errno values
```

## Key Differences from Linux

| Feature | Linux | FreeBSD |
|---------|-------|---------|
| I/O multiplexing | epoll | kqueue |
| Socket options | different bit positions | different bit positions |
| `stat.st_ino` | 64-bit (x86_64) | 32-bit (x86 FreeBSD) |
| Process isolation | namespaces/seccomp | jail/Capsicum |
| Sendfile | `sendfile(int,int,off_t*,size_t)` | different prototype |
| sysctl | `/proc/sys` + syscall | direct `sysctl()` syscall |

## Load alongside

```r2
to libc/functions.h      # POSIX base functions (shared with Linux)
to libc/socket.h         # socket structs (sockaddr etc. are identical)
to freebsd/freebsd.h     # BSD extensions
```

## Notes

- `kqueue` + `kevent` is the FreeBSD event loop primitive — the equivalent of
  Linux `epoll`. Virtually every server daemon on FreeBSD uses it.
- Capsicum (`cap_enter`, `cap_rights_limit`) is FreeBSD's capability model.
  Finding `cap_enter()` calls shows sandbox boundaries.
- `jail_attach` / `jail_set` calls indicate container/isolation logic.
