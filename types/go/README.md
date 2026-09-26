# types/go/ -- Go runtime internal type definitions

Covers Go 1.18+ runtime internals for analysis of stripped Go binaries,
Go malware, and Go-based cloud-native tools.

## Usage

```r2
to go/runtime.h
tsc go_g        -- goroutine descriptor (96 fields, amd64 layout)
tsc go_hchan    -- channel header
tsc go_hmap     -- map header
tsc go_iface    -- interface value (tab + data)
tsc go_eface    -- empty interface (type + data)
tsc go_slice    -- slice header (ptr + len + cap)
tsc go_string   -- string header (ptr + len, NOT null-terminated)
te  go_gstatus  -- goroutine status codes
te  go_kind     -- reflect.Kind constants
```

## Loaded by

- `profiles/linux-go-amd64.r2`
- `profiles/linux-go-arm64.r2`

## Notes

- `go_g` struct layout matches Go 1.21-1.23 amd64. Minor offsets change
  across versions; use `go version` on the binary to confirm version.
- Go strings are (ptr, len) -- NOT null-terminated. Use `psb @ ptr` in r2.
- Goroutine pointer location: amd64=TLS[fs:-8], arm64=R28, x86=TLS[gs:-4]
- Channel status: qcount=0 and recvq != nil means goroutines are blocked.
