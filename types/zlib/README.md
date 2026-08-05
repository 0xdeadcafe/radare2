# zlib Type Definitions for radare2

Type definitions for the zlib compression library.

## Files

| File | Contents |
|------|----------|
| `zlib.h` | z_stream struct, gz_header, constants, function signatures |

## Usage

```r2
# Load zlib types
to types/zlib/zlib.h

# Look up flush values
te zlib_flush

# Look up return codes
te zlib_error

# Show z_stream structure
ts z_stream

# Apply struct to memory
tp z_stream @ 0x1000

# Show function signature
tfc deflate
tfc inflate
```

## Quick Reference

### Return codes
```
Z_OK = 0           - Success
Z_STREAM_END = 1   - End of stream
Z_NEED_DICT = 2    - Dictionary needed
Z_ERRNO = -1       - File error (check errno)
Z_STREAM_ERROR = -2 - Invalid stream state
Z_DATA_ERROR = -3  - Data corrupted
Z_MEM_ERROR = -4   - Out of memory
Z_BUF_ERROR = -5   - Buffer too small
Z_VERSION_ERROR = -6 - Version mismatch
```

### Compression levels
```
Z_NO_COMPRESSION = 0
Z_BEST_SPEED = 1
Z_BEST_COMPRESSION = 9
Z_DEFAULT_COMPRESSION = -1
```

### Flush values
```
Z_NO_FLUSH = 0
Z_PARTIAL_FLUSH = 1
Z_SYNC_FLUSH = 2
Z_FULL_FLUSH = 3
Z_FINISH = 4
```

## z_stream Structure

The main state structure for compression/decompression:

```c
struct z_stream {
    void *next_in;      /* input buffer pointer */
    uint32_t avail_in;  /* bytes available in input */
    uint64_t total_in;  /* total bytes read */
    void *next_out;     /* output buffer pointer */
    uint32_t avail_out; /* space in output buffer */
    uint64_t total_out; /* total bytes written */
    char *msg;          /* error message or NULL */
    void *state;        /* internal state */
    ...
};
```

## Combining with zsigs

```r2
# Load Debian amd64 zlib signatures
zo zigns/debian/amd64/zlib.zsig

# Load type information
to types/zlib/zlib.h

# Analyze
aaa
z/              # Match signatures

# Annotate z_stream at function argument
tp z_stream @ rdi
```
