# r2 Corpus TODO

Last updated: 2026-08-28
Run `python3 tool/validate-corpus.py` to confirm current state.

Priority: **P1** blocks analysis · **P2** coverage/quality gap · **P3** cleanup/docs

---

## P1 — Blocks Analysis Quality

### P1-1 `aether_r2profile.py` hardcodes `~/.local/share/radare2`

`_r2_share()` calls `os.path.expanduser("~/.local/share/radare2")` directly.
Every other tool in `tool/` respects `R2_DATA_DIR` (env override). When corpus
is mounted at a non-default path (e.g. a non-root bare-metal install where
`$HOME` differs) the auto-profile loader silently fails to find profiles and zsigs.

**Fix:** Replace the hardcoded path with:
```python
def _r2_share() -> str:
    if "R2_DATA_DIR" in os.environ:
        return os.environ["R2_DATA_DIR"]
    rdatahome = os.environ.get("R2_RDATAHOME", os.path.join(Path.home(), ".local", "share"))
    return os.path.join(rdatahome, "radare2")
```

**File:** `scripts/aether_r2profile.py` line ~122

---

### P1-2 macOS zsigs: ~1% named — most post-match functions stay `fcn.*` ✅ FIXED

**Root cause confirmed:** r2 maps Mach-O MH_OBJECT `__text` sections to vaddr=0x0
and refuses to analyze code there. Single-function files like `cbrt.c` produced 0
named entries; only multi-function files where some symbols have non-zero vaddrs
produced any names.

**Fix (2026-08-28):** `generate-macos-zsig.py` rewritten to use flat-binary extraction:
1. `get_function_layout()` uses `llvm-nm` + `rabin2` to compute each exported
   function’s file offset and size from consecutive symbol offsets
2. For each function, raw bytes are extracted from the object file and opened
   as a flat ARM64/x86-64 binary — no Mach-O parser involved
3. `af @ 0; afn name; zg` analyses and names the function correctly
4. All extracted functions are 100% named; no `fcn.*` pollution

**Result:**

| zsig | Before | After |
|------|-------:|------:|
| arm64/libm | 75 named | **150 named** |
| arm64/libSystem | 145 named | **311 named** |
| x86_64/libm | 223 named | **363 named** |
| x86_64/libSystem | 152 named | **319 named** |

jq arm64 z/ matches: **8 → 20 named functions**
(cbrt, acosh, asinh, atanh, cosh, exp2, expm1, fdim, lgamma, logb,
nextafter, nexttoward, remainder, tanh now correctly identified)

---

## P2 — Coverage Gaps

### P2-1 OpenSSL static library zsigs against musl

`debian/{amd64,arm64,armhf,i386}/libssl.zsig` exist (Batch 2). Missing: OpenSSL
compiled against musl libc — common in Alpine-based containers, OpenWrt packages
with TLS, and custom embedded builds.

**Action:**
```bash
# Build OpenSSL against musl cross-compiler (Bootlin toolchain or Alpine SDK)
# Output: musl/aarch64/libssl.zsig, musl/x86_64/libssl.zsig, musl/arm/libssl.zsig
python3 tool/generate-zsig.py --lib libssl.a -o zigns/musl/aarch64/libssl.zsig
```

**Blocked by:** Requires musl-linked OpenSSL build. Bootlin toolchain includes
musl headers; OpenSSL builds cleanly against them with `./Configure no-shared`.

---

### P2-2 Session zsigs for jrc, navico, raymarine, hpe-ilo7

Four targets have profiles and confirmed symbols but no corpus session zsigs.
`coverage.json` shows `zsigs=False` for all four.

| Target | Profile | Gap |
|--------|---------|-----|
| `arm-jrc` | `profiles/icom-vxworks-mips.r2` (shared) | Need JRC firmware binary |
| `arm-navico` | (linux-glibc-arm32.r2) | Need Navico/Simrad firmware binary |
| `arm-raymarine` | (linux-glibc-arm32.r2) | Need Raymarine firmware binary |
| `aarch64-hpe` | `hpe-ilo7-arm64.r2` | Need HPE iLO 7 firmware binary |

**Action:** Obtain firmware → run full analysis session → `corpus_commit.py`
generates session zsig automatically. No manual work needed once binary is present.

---

### P2-3 Zephyr RTOS zsigs for bare-metal Cortex-M

Many IoT devices (Nordic nRF52/53, STM32WL, ESP32 with Zephyr) use Zephyr RTOS
alongside or instead of FreeRTOS. Key functions: `k_sleep`, `k_msleep`,
`k_sem_give`, `k_msgq_put`, `net_pkt_alloc`, `bt_gatt_notify`.

**Action:**
```bash
# Clone Zephyr, build for Cortex-M4 target (boards/arm/nrf52840dk_nrf52840)
python3 tool/generate-freertos-zsig.py   # extend or add generate-zephyr-zsig.py
# Output: zigns/embedded/arm-none-eabi/zephyr-cm4.zsig
```

**Blocked by:** Zephyr build system (west + cmake) is more complex than FreeRTOS.
Needs ~1 hour to write `generate-zephyr-zsig.py` using the same clang approach.

---

## P3 — Cleanup / Docs

### P3-1 `CONSTITUTION.md` structure diagram stale

The `Structure` section lists `zigns/` subdirs without `macos/`, `go/`. Does not
mention `zigns/tiers.json` or `profiles/profiles_config.json`.

**Fix:** Update the tree in `CONSTITUTION.md` to add:
```
│   ├── tiers.json       # tier taxonomy (core/vendor/debian-large/windows-large)
│   ├── macos/           # vendor tier
│   └── go/              # vendor tier
└── profiles/
    ├── profiles_config.json  # auto-profile routing schema
```

---

### P3-2 `de2cc34b9686e5da` session: 510 `fcn.*` entries still in zsig file

Index correctly shows `entry_count=510, named_pct=0`. The zsig was supposed to be
emptied ("file retained as empty zsig to preserve index integrity") but r2's `zos`
on an empty session doesn't truncate an existing file. The 510-entry file has zero
cross-binary value and wastes ~23 KB.

**Fix:**
```bash
# Overwrite with a truly empty zsig binary
r2 -q2 -c "zos /path/to/de2cc34b9686e5da.zsig" malloc://1
# Verify: r2 -q2 -c "zo de2cc34b9686e5da.zsig; z~?" malloc://1  →  0
```
Or simply delete the file and remove the index entry (the session is self-referential
and was never useful).

---

## Coverage Gaps — Waiting on Firmware

These are tracked in `coverage.json` as `zsigs=False`. No tooling work needed —
just firmware acquisition.

| Target | Arch | Profile | Blocker |
|--------|------|---------|---------|
| `arm-jrc` | ARM32 | (shared with icom/vxworks) | Need JRC VSAT firmware |
| `arm-navico` | ARM32 glibc | linux-glibc-arm32.r2 | Need Navico/Simrad chart-plotter firmware |
| `arm-raymarine` | ARM32 glibc | linux-glibc-arm32.r2 | Need Raymarine firmware |
| `aarch64-hpe` | AArch64 | hpe-ilo7-arm64.r2 | Need HPE iLO 7 firmware image |

---

## Quick Commands

```bash
# Validate corpus
cd /opt/aether/skel/.local/share/radare2
python3 tool/validate-corpus.py

# Check coverage gaps
python3 -c "
import json
cov = json.load(open('coverage.json'))
for k,v in sorted(cov.items()):
    if isinstance(v,dict) and not v.get('zsigs',True):
        print(f'  {k}: profile={v.get(\"profile\",\"?\")} vendor={v.get(\"vendor\",\"?\")}')
"

# Prune session zsigs
python3 tool/prune-session-zsigs.py --r2dir . --dry-run

# Regenerate macOS zsigs (cached after first run)
R2_DATA_DIR=. python3 tool/generate-macos-zsig.py --force
```
