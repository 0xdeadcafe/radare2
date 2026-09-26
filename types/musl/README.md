# musl libc Type Definitions

Type definitions for musl libc reverse engineering.

## Files

| File | Content |
|------|---------|
| `functions.h` | musl-specific function signatures (common internals) |
| `functions-zsig.h` | zsig-variant names for aaft matching (300+ functions) |

## Usage

```r2
# Load musl function signatures
to types/musl/functions.h

# For zsig-matched functions, also load:
to types/musl/functions-zsig.h

# For standard libc types:
to types/libc/functions.h
to types/libc/errno.h

# Apply types to analyzed functions
aaft
```

## Zsig Integration

When using musl zsigs (`zo zigns/musl/<arch>/musl-libc.zsig`), functions are
identified with names like `sym.__malloc_usable_size`. The `aaft` command only
matches exact function names against type definitions.

The `functions-zsig.h` file provides type definitions using the exact names
that zsig matches produce, enabling automatic type application:

```r2
# Full workflow for stripped musl binary
zo zigns/musl/aarch64/musl-libc.zsig
to types/musl/functions-zsig.h
to types/libc/functions.h
aaa
z/
aaft  # Now types are applied to zsig-matched functions
```

## Notes

- musl is mostly POSIX-compatible; `types/libc/` covers most functions
- `functions.h` contains musl-specific extensions and internal functions
- `functions-zsig.h` adds 300+ internal function signatures for zsig matching
