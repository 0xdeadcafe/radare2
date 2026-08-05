# Modality Firmware Analysis Workflows

Modality is an r2 core plugin (`r2pm -i modality`) that embeds angr symbolic
execution inside a live r2 session as `M` commands. All function names, CC
annotations, and seek positions from static analysis carry over directly — no
tool switch needed.

**Prerequisites:**
- `aa` has been run (function list populated)
- A1 PLT resolve has run (`resolve_mips_plt(r2)` via `load_profile`)
- `R2ANGR_STDIN_SIZE` env var set (default 1024 since F1 patch)

```bash
export R2ANGR_STDIN_SIZE=1024   # set before opening r2; firmware packets need >150 bytes
```

---

## Workflow 1 — CMD_INJECTION / AUTH_BYPASS

Use when: static analysis found `system()` / `popen()` / `execve()` called with
user-controlled data, or `strcmp` auth bypass.

**Inputs needed from static analysis:**
- `<network_entry_addr>` — packet parser entry point (where `recv()` data enters)
- `<sink_addr>` — the `system()` / `strcmp` call site
- `<error_handler_addr>` — addresses of error/reject paths to avoid (optional but faster)

```r2
# 1. Seek to the network input handler
s <network_entry_addr>        # e.g. s 0x402fd0  (clisrv.packet_parser)

# 2. Initialise a blank angr state at this address
Mib                           # blank state; stdin is symbolic (R2ANGR_STDIN_SIZE bytes)

# 3. Annotate the goal (find) and dead paths (avoid)
CC find @ <sink_addr>         # e.g. CC find @ 0x401500   (system() call site)
CC avoid @ <error_handler>    # e.g. CC avoid @ 0x404560  (error return path)
CC avoid @ <another_dead>     # add as many CC avoid as needed

# 4. Hook all named PLT functions as SimProcedures
#    Requires A1 PLT resolve — without it, system()/printf() are unnamed and unhookable.
Mhf

# 5. Explore
Me                            # angr walks the CFG toward the CC find target (120s max)

# 6. Extract the concrete exploit input
Msi                           # prints stdin bytes that reached the sink
```

**Expected output of `Msi`:**
```
[R2ANGR] stdin bytes: 55 0f 04 00 00 19 00 c0 08 00 00 00 <payload> a2 96 30
```

Embed these hex bytes in the finding note and in the PoC Python script.

**If `Me` times out (>120s):**
- Add more `CC avoid` entries on loop-heavy functions and retry
- Use `Msl` to inspect active states and identify where angr is stuck
- Reduce `R2ANGR_STDIN_SIZE` if only the header bytes matter for path selection
- Mark finding as `REACHABILITY_UNPROVEN` and document the static evidence

---

## Workflow 2 — CRC / Checksum Solving

Use when: CRC gate is blocking the path to the sink, or you need to construct a
valid protocol frame (e.g. DJI DUPC CRC8 + CRC16).

**Inputs needed:**
- `<crc_function_addr>` — from `/m crypto_tables.magic` + `axt` (e.g. `clisrv.crc8` @ 0x401ab0)
- The constrained bytes (known header bytes, e.g. `[0x55, 0x0f, 0x04]`)

```bash
export R2ANGR_STDIN_SIZE=64   # just the header bytes; smaller = faster
```

```r2
s <crc_function_addr>         # e.g. s 0x401ab0  (clisrv.crc8)
Mib                           # blank state at CRC function entry

# Annotate the address AFTER the CRC result is stored/returned
CC find @ <addr_after_crc>    # e.g. CC find @ 0x401b00 (after crc8 return)

Me                            # explore: angr walks to the CRC output
Mbs                           # solve: prints the concrete CRC byte(s) for the symbolic input
```

**DJI DUPC CRC example** (proven: <1 second):
```r2
s 0x401ab0                    # clisrv.crc8
Mib
CC find @ 0x401b00
Me
Mbs
# Output: CRC8 = 0xa2 for input [0x55, 0x0f, 0x04]
```

---

## Workflow 3 — Command Dispatch Enumeration

Use when: the cmd_id→handler mapping is unknown (e.g. jump table with gap entries
that make manual counting error-prone).

**Proven:** caught an off-by-3 error in manual P3C analysis (cmd_id 0x19 vs. 0x1c
for enable_telnetd handler).

**Inputs needed:**
- `<dispatcher_entry_addr>` — dispatch function entry point
- List of candidate handler addresses (from `pdf @ <dispatcher>` jump table)

```r2
s <dispatcher_entry_addr>     # e.g. s 0x404b30  (clisrv.wifi_cmd_handler)
Mib

# Annotate each candidate handler as a find target
CC find @ 0x406168            # enable_telnetd handler
CC find @ 0x406200            # disable_telnetd handler
CC find @ 0x4062c0            # set_ssid handler
# ... one CC find per handler you want to map

Me                            # explore to all annotated handlers simultaneously

Msl                           # list which state landed at which address
Msi                           # print the cmd_id byte that routes to each handler
```

**Output:** `Msl` shows a state per matched handler; `Msi` on each reveals the
concrete cmd_id value. This correctly accounts for jump table gaps and default cases.

---

## Workflow 4 — DJI `set_ssid → system()` One-Off Hook

`clisrv.wifi_cmd_handler` calls a firmware-specific function `set_ssid` which
internally calls `system()`. `Mhf` hooks PLT stubs but not non-PLT internal
calls like this. Add a manual SimProcedure annotation:

```r2
# After Mib, before Mhf:
# Annotate set_ssid as a "reaches system()" waypoint so angr models it correctly
CC find @ 0x4041dc            # clisrv.fw_flash (or whichever internal fn calls system())
```

Alternatively, if set_ssid is at a known address and you need it to be transparent
to angr, mark it as `CC avoid` so angr skips it and keeps exploring via other paths:

```r2
CC avoid @ <set_ssid_entry>   # tell angr not to enter this function
```

---

## Troubleshooting

### State explosion (`Me` runs indefinitely, state count grows >1000)

1. **Add more `CC avoid` entries** on high-fan-out functions (logging, string ops):
   ```r2
   CC avoid @ sym.imp.printf
   CC avoid @ sym.imp.sprintf
   CC avoid @ sym.imp.memcpy
   ```
2. **Reduce stdin size**: `export R2ANGR_STDIN_SIZE=64` and restart the session
3. **Use `Msk <n>`** to kill states that have diverged too far from the target
4. **Kill loop-heavy states**: use `Msl` to identify states stuck in loops,
   then `Msk <index>` to kill them

### `Mhf` hooks nothing / Modality can't find `system()`

- **Root cause:** PLT stubs are unnamed (`fcn.004010c0`) — A1 PLT resolve did not run
- **Fix:** call `resolve_mips_plt(r2)` from `aether_r2profile.load_profile()`,
  or run `r2.cmd("#!pipe python3 /aether/scripts/mips_plt_resolve.py --pipe")`
- **Verify:** `afl~sym.imp` should show `sym.imp.system`, `sym.imp.printf`, etc.

### `Mib` crashes with architecture error

- **Root cause:** Modality pre-F1 patch hardcoded x86 registers
- **Fix:** F1 patches already applied — ensure `~/.local/share/radare2/r2pm/git/Modality/`
  is the patched version (check `grep -n "_ip\|auto_load_libs=False" src/initializer.py`)

### Blank state on MIPS: `recv()` returns nothing / path doesn't reach target

- **Root cause:** blank state has no `$gp` register — GOT-relative loads return 0
- **Fix:** F1 patch sets `state.regs.gp` automatically for MIPS — confirm patch is applied
- **Manual workaround:** `Mbr gp` to symbolize `$gp`, then constrain it:
  `Mib` → manually set `$gp` via r2: `dr gp=<got_section_va>`

---

## Environment Setup Reference

```bash
# Recommended before any Modality session on firmware:
export R2ANGR_STDIN_SIZE=1024   # DJI DUPC max is 2047; Cobham BGAN is 512+

# For CRC solving (only header bytes needed):
export R2ANGR_STDIN_SIZE=64

# Verify Modality is installed and F1 patches are applied:
r2 -q -c "M?" /dev/null 2>/dev/null | head -5
grep -c "auto_load_libs=False" ~/.local/share/radare2/r2pm/git/Modality/src/initializer.py
# Should print: 2
```
