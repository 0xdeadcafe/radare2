# vxworks_kernel.r2 — Icom AP-90M VxWorks 6.9 kernel (MIPS32 BE)
# Binary: carved.elf (from ap90mv2_30_11.dat, 52-3710224.elf32_extract)
# SHA256: 8b275fba0e62d4b3b4c7c39c1119176ec254e49ae1ec6263e72b63ad342c73c4
#
# NOTE: This binary is NOT stripped — it has 72 named FUNC symbols in its .symtab
# (cons_puts, dcacheFlush, LzmaDec_*, bcopy*, LzmaDec_DecodeToDic, etc.).
# These are loaded automatically by r2 via 'is' when the ELF is opened.
# No additional flag definitions needed here.
#
# The single interrupt handler below was identified during triage.
# Profile: icom-ap90m-vxworks.r2 or icom-vxworks-mips.r2

f int.001c0566 83 @ 0x1c0566
