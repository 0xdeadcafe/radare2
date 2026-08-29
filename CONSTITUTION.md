# Constitution

## Purpose

Generate **content** that enriches radare2's dataset where it's missing, improving reverse engineering quality and efficacy.

**We produce data, not software.**

## Single Source of Truth

`skel/.local/share/radare2/` (this directory) is the **one canonical location** for all r2 knowledge.
There are no other copies maintained in parallel.

| What lives here | What does NOT live here |
|---|---|
| types, profiles, magic, format, symbols | Vault findings, PoCs, target recon |
| radare2rc defaults | Per-target analysis artefacts |
| tool/ generators | Binary blobs, core dumps |
| zigns/ (corpus + session zsigs, committed to git) | Duplicate copies anywhere |

**Vault** (`vault/`) holds target-specific knowledge (Findings, Targets, Patterns, PoCs).
It never holds copies of r2 configuration — those live here only.

**Write-back:** when a skill session discovers new named functions, struct types, or
pf templates, `corpus_commit.py` writes them directly here. Because this directory
is bind-mounted read-write in docker-compose, every discovery persists to the host repo
immediately — no manual rsync needed.

**Zignatures:** corpus and session `.zsig` databases are committed to git under
`zigns/`. The `install.sh --copy` (or `--symlink`) step deploys them to
`~/.local/share/radare2/zigns/` where r2 can load them via `dir.zigns`.
The `zigns/` directory here contains only a `.gitkeep` placeholder so the Docker
bind mount path always exists. Running without external zigns is gracefully degraded
(session-generated zigs still work).

## Principles

### 1. Content Over Code
- Output: magic signatures, zignatures, format definitions, type definitions
- Code exists only to generate content
- If r2 already has it, don't add it

### 2. Simplicity
- Every file must justify its existence
- Scripts should be obvious and minimal
- When in doubt, leave it out

### 3. Reusable RE Corpus
- Prefer reusable signatures for libraries, runtimes, ABIs, protocols, and containers
- Target/vendor-specific data is welcome when confirmed and useful beyond one ephemeral session
- Firmware is a first-class use case, not the boundary of the corpus

## What Belongs Here

| Directory | Purpose | Examples |
|-----------|---------|----------|
| `zigns/` | Library function signatures | libc, musl, Android NDK, Windows SDK |
| `magic/` | File format signatures | Headers and file/container markers r2 lacks |
| `format/` | Structure definitions | `pf` templates for binary/container structures |
| `types/` | Type definitions | C headers for ABI, library, platform, and target structures |
| `tool/` | Content generators | Scripts that produce the above |
| `radare2rc` | Sensible defaults | Display/analysis settings |

## What Doesn't Belong

- **Wrappers** - Use r2 directly
- **Aliases** - Learn real commands
- **Duplicate signatures** - Check r2 first: `r2 -qc '/m' file`
- **Complex tools** - If it needs tests, it's too complex
- **Large binaries** - Generate locally, commit only the output data

## Decision Process

1. Does r2 already do this? → **Don't add**
2. Is it a file/container signature? → `magic/`
3. Is it a library signature? → `zigns/`
4. Is it a structure? → `format/` or `types/`
5. Does it generate any of the above? → `tool/`
6. Is it complex? → **Simplify or don't add**

## Tool Standards

Keep tools simple:
- Single-file Python or shell scripts
- Self-documenting (`--help`)
- No external dependencies beyond r2pipe
- Readable in 5 minutes

## Structure

```
skel/.local/share/radare2/   (deployed to ~/.local/share/radare2/ by skel/install.sh)
├── magic/                 # → ~/.local/share/radare2/magic/
├── format/                # → ~/.local/share/radare2/format/
├── types/                 # → ~/.local/share/radare2/types/
├── zigns/                 # → ~/.local/share/radare2/zigns/
│   ├── tiers.json           # tier taxonomy (core/vendor/debian-large/windows-large)
│   ├── android/             # vendor tier
│   ├── cisco-ios/           # vendor tier
│   ├── debian/              # debian-large tier (amd64/arm64/armhf/i386)
│   ├── dji/                 # vendor tier
│   ├── embedded/            # core tier (FreeRTOS + Newlib Cortex-M)
│   ├── go/                  # vendor tier
│   ├── juniper/             # vendor tier
│   ├── macos/               # vendor tier (libSystem + libm)
│   ├── musl/                # core tier
│   ├── openwrt/             # core tier
│   ├── uclibc/              # core tier (mips32/64, arm32, arm64)
│   ├── vxworks/             # vendor tier
│   ├── windows/             # windows-large tier
│   └── sessions/            # local only — written during analysis
├── profiles/              # → ~/.local/share/radare2/profiles/
│   ├── profiles_config.json # auto-profile routing schema
│   └── libc/                # libc sub-profiles (sourced by vendor profiles)
├── scripts/               # → ~/.local/share/radare2/scripts/
│   └── windows-sinks.r2     # PE security sink labeler (sourced by windows profiles)
├── symbols/               # → ~/.local/share/radare2/symbols/
├── plugins/               # → ~/.local/share/radare2/plugins/  (Modality plugin.py)
├── modality/              # → ~/.local/share/radare2/modality/  (angr/Z3 bridge source)
├── tool/                  # Content generators (run from repo, not installed)
├── coverage.json          # Arch/vendor coverage matrix
├── TODO.md                # Open work items
└── docs/                  # Protocol RE notes and workflow references
```
