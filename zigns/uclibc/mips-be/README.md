# uclibc/mips-be — INTENTIONALLY EMPTY

The `uclibc/mips32/uclibc-libc.zsig` covers **both** MIPS32 big-endian and
little-endian targets. It was built from uClibc-ng 0.9.33 for `mips32-unknown-linux-uclibc`
(big-endian), which is the DJI/OpenWrt MIPS BE toolchain target.

For MIPS32 big-endian uClibc binaries, use:
  `zo uclibc/mips32/uclibc-libc.zsig`

This directory exists as a documentation placeholder — no separate zsig is needed
because byte-level MIPS instruction encoding differs between BE and LE, and the
`uclibc/mips32/` zsig was generated from BE sources. The r2 `z/` matching engine
handles the endian-specific byte patterns correctly.

Profile: `profiles/libc/uclibc-mips32.r2` handles both BE and LE targets.
