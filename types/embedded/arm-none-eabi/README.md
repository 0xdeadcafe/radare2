# Newlib Type Definitions (arm-none-eabi)

Type headers for Cortex-M newlib functions.

## Status: Needs Regeneration

Previous type headers were generated from DWARF info but all function
signatures resolved to `void f(void)` — the DWARF extraction dropped every
parameter and return type. Loading those files would annotate functions with
wrong signatures, which is worse than having no annotation at all.

The corresponding zsig files in `zigns/embedded/arm-none-eabi/` are correct
and still useful for function identification.

## Regenerating

Requires a debug build of newlib (compiled with `-g`):

```bash
# Download arm-none-eabi toolchain with debug newlib
# Then extract DWARF types
llvm-dwarfdump --all libc.a | ... # extract structs/enums
# Or use the generate-zsig.py --types flag against a debug build
./tool/generate-zsig.py --lib path/to/debug/libc.a --types -o newlib-v7em-types.h
```

Separate files per CPU variant because newlib's math library
differs between Cortex-M profiles (FPU availability affects
the libm implementation):

| File | Target | Zsig |
|------|--------|------|
| `newlib-v6m-types.h` | Cortex-M0/M0+ | `zigns/embedded/arm-none-eabi/newlib-v6m.zsig` |
| `newlib-v7m-types.h` | Cortex-M3 | `zigns/embedded/arm-none-eabi/newlib-v7m.zsig` |
| `newlib-v7em-types.h` | Cortex-M4/M7 | `zigns/embedded/arm-none-eabi/newlib-v7em.zsig` |
| `newlib-libm-v7em-types.h` | Cortex-M4/M7 libm | `zigns/embedded/arm-none-eabi/newlib-libm-v7em.zsig` |
