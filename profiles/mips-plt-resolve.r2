# mips-plt-resolve.r2 — Rename MIPS PLT trampolines to sym.imp.<name>
#
# Each MIPS PLT stub (lui/lw/jr/nop, 16 bytes) stays named fcn.XXXXXXXX after
# `aa` because r2 cannot resolve the GOT indirection on its own.  This profile
# cross-references irj (relocations) against aflj (function list) to rename
# all matching stubs.  After sourcing this, `axtj @ sym.imp.system` works and
# Modality's `Mhf` can hook all PLT functions automatically.
#
# Requires: aa already run in the session.
#
# Usage:
#   Interactive r2 session:
#     . ~/.local/share/radare2/profiles/mips-plt-resolve.r2
#
#   From another profile (e.g. linux-uclibc-mips.r2 or dji-wifi.r2):
#     . ~/.local/share/radare2/profiles/mips-plt-resolve.r2
#
#   Programmatic (r2pipe) — preferred:
#     # See tool/mips_plt_resolve.py if you have it installed:
#     #   r2.cmd("#!pipe python3 ~/.local/share/radare2/scripts/mips_plt_resolve.py")
#     # Or iterate relocations manually:
#     #   for rel in r2.cmdj('irj'): r2.cmd(f"afn sym.imp.{rel['name']} {rel['plt']}")
#
# Native r2 equivalent (no Python required — rename stubs from relocation table):

# For each relocation that has a named symbol and points into the PLT,
# flag it so callers resolve correctly.  r2 built-in command:
#   afna   — auto-name functions based on xrefs and relocation table
# Run after aa:
afna
?e [mips-plt-resolve] PLT stubs renamed via afna. Use 'axtj @ sym.imp.FUNC' to find callers.
