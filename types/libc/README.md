# Linux libc Type Definitions for radare2

Type definitions for Linux C library functions and structures.

## Files

| File | Contents |
|------|----------|
| `errno.h` | Linux errno values (EPERM, ENOENT, etc.) |
| `signal.h` | Signal numbers (SIGKILL, SIGSEGV, etc.) |
| `socket.h` | Socket types, address families, sockaddr structs |
| `fcntl.h` | File operations, open flags, stat struct, mmap flags |
| `functions.h` | Common libc function signatures |

## Usage

```r2
# Load all libc types
to types/libc/errno.h
to types/libc/signal.h
to types/libc/socket.h
to types/libc/fcntl.h
to types/libc/functions.h

# Look up errno value
te linux_errno 13           # EACCES

# Look up signal
te linux_signal 11          # SIGSEGV

# Show socket types
te linux_af                 # Address families
te linux_sock_type          # SOCK_STREAM, etc.

# Show open flags
te linux_open_flags

# Show function signature
tfc malloc
tfc socket

# Apply struct to memory
tp sockaddr_in @ 0x1000
tp stat @ 0x2000
```

## Quick Reference

### Common errno values
```
EPERM = 1      - Operation not permitted
ENOENT = 2     - No such file or directory
ESRCH = 3      - No such process
EINTR = 4      - Interrupted system call
EIO = 5        - I/O error
EBADF = 9      - Bad file descriptor
ENOMEM = 12    - Out of memory
EACCES = 13    - Permission denied
EFAULT = 14    - Bad address
EEXIST = 17    - File exists
EINVAL = 22    - Invalid argument
EPIPE = 32     - Broken pipe
```

### Common signals
```
SIGINT = 2     - Interrupt (Ctrl+C)
SIGQUIT = 3    - Quit
SIGILL = 4     - Illegal instruction
SIGABRT = 6    - Abort
SIGKILL = 9    - Kill (cannot be caught)
SIGSEGV = 11   - Segmentation fault
SIGTERM = 15   - Termination
```

### Socket constants
```
AF_INET = 2    - IPv4
AF_INET6 = 10  - IPv6
AF_UNIX = 1    - Unix domain

SOCK_STREAM = 1 - TCP
SOCK_DGRAM = 2  - UDP
SOCK_RAW = 3    - Raw socket
```

### Open flags
```
O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2
O_CREAT = 64
O_TRUNC = 512
O_APPEND = 1024
```

## Architecture Notes

The struct definitions (stat, sockaddr) are for **x86_64 Linux**.
ARM and 32-bit systems have different layouts due to:
- Different type sizes (long is 4 bytes on 32-bit)
- Different struct padding
- Different field order in some cases

For architecture-specific analysis, verify struct layouts against
the target system's headers.

## Combining with zsigs

Load types alongside function signatures:

```r2
# Load Debian amd64 signatures
zo zigns/debian/amd64/libc6.zsig

# Load type information
to types/libc/functions.h
to types/libc/errno.h

# Analyze
aaa
z/              # Match signatures
```
