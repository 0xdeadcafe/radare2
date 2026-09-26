#!/usr/bin/env python3
"""validate-corpus.py — Cross-check r2 corpus consistency.

Verifies that every profile, zsig directory, symbol file, and
coverage/profiles_config entry actually corresponds to a file that exists.
Prints a structured diff and exits non-zero if anything is broken.

Usage:
    python3 tool/validate-corpus.py
    python3 tool/validate-corpus.py --fix    # auto-remove dead symlinks (dry-run by default)
    python3 tool/validate-corpus.py --json   # machine-readable output

Run from the skel root or any directory; the corpus root is auto-detected
from this file's location.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# ── Locate corpus root ────────────────────────────────────────────────────────

SCRIPT_DIR   = Path(__file__).resolve().parent          # skel/.local/share/radare2/tool/
CORPUS_ROOT  = SCRIPT_DIR.parent                        # skel/.local/share/radare2/
PROFILES_DIR = CORPUS_ROOT / "profiles"
ZIGNS_DIR    = CORPUS_ROOT / "zigns"
SYMBOLS_DIR  = CORPUS_ROOT / "symbols"
TYPES_DIR    = CORPUS_ROOT / "types"
MAGIC_DIR    = CORPUS_ROOT / "magic"

# profiles_config.json normally lives in the repo's scripts/ directory next to
# aether_r2profile.py.  Also support a local corpus copy and the container
# install path used by AETHER images.
_pc_candidates = [CORPUS_ROOT / "profiles_config.json"]
for _parent in SCRIPT_DIR.parents:
    _candidate = _parent / "scripts" / "profiles_config.json"
    if _candidate.exists():
        _pc_candidates.append(_candidate)
        break
_pc_candidates.append(Path("/aether/scripts/profiles_config.json"))
PROFILES_CONFIG = next((p for p in _pc_candidates if p.exists()), _pc_candidates[0])
COVERAGE_JSON   = CORPUS_ROOT / "coverage.json"
SESSION_INDEX   = ZIGNS_DIR / "sessions" / "index.json"

ERRORS   = []
WARNINGS = []


def err(msg):  ERRORS.append(msg)
def warn(msg): WARNINGS.append(msg)
def ok(msg):   pass  # Could collect passing checks if needed


# ── Check 1: profiles_config.json references valid profile files ──────────────

_ARCH_COMPAT = {
    "arm": {"arm"},       # r2 uses asm.arch=arm for both ARM32 and AArch64
    "aarch64": {"arm"},
    "arm64": {"arm"},
    "mips": {"mips"},
    "mipsel": {"mips"},  # endianness is cfg.bigendian, not asm.arch
    "x86": {"x86"},
    "x86_64": {"x86"},
    "ppc": {"ppc"},
    "powerpc": {"ppc"},
}


def _profile_text_with_sources(profile_path: Path, seen=None) -> str:
    """Return profile text plus same-corpus profiles sourced via `. /.../profiles/foo.r2`."""
    if seen is None:
        seen = set()
    if profile_path in seen or not profile_path.exists():
        return ""
    seen.add(profile_path)
    text = profile_path.read_text(errors="replace")
    chunks = [text]
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith(". ") or line.startswith("#"):
            continue
        token = line[2:].split()[0]
        marker = "/profiles/"
        if marker in token:
            rel = token.split(marker, 1)[1]
            chunks.append(_profile_text_with_sources(PROFILES_DIR / rel, seen))
    return "\n".join(chunks)


def _forced_asm_arch(profile_path: Path) -> str | None:
    for raw in _profile_text_with_sources(profile_path).splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if line.startswith("e asm.arch="):
            return line.split("=", 1)[1].split()[0].strip()
    return None


def check_profiles_config():
    if not PROFILES_CONFIG.exists():
        err(f"profiles_config.json missing: {PROFILES_CONFIG}")
        return

    cfg = json.loads(PROFILES_CONFIG.read_text())

    for section in ("arch_profiles", "vendor_profiles", "libc_profiles"):
        for key, profile_file in cfg.get(section, {}).items():
            path = PROFILES_DIR / profile_file
            if not path.exists():
                err(f"profiles_config.json [{section}] {key!r} → {profile_file!r}  ← FILE NOT FOUND")
                continue
            ok(f"  ✓ {section}/{key} → {profile_file}")

            expected_arch = key.split("/", 1)[0].lower()
            forced_arch = _forced_asm_arch(path)
            allowed = _ARCH_COMPAT.get(expected_arch)
            if forced_arch and allowed and forced_arch not in allowed:
                err(
                    f"profiles_config.json [{section}] {key!r} → {profile_file!r} "
                    f"forces asm.arch={forced_arch!r}, expected one of {sorted(allowed)!r}"
                )


# ── Check 2: coverage.json sanity ────────────────────────────────────────────

def check_coverage():
    if not COVERAGE_JSON.exists():
        warn(f"coverage.json missing: {COVERAGE_JSON}")
        return

    cov = json.loads(COVERAGE_JSON.read_text())
    for key, entry in cov.items():
        vendor   = entry.get("vendor", "")
        has_prof = entry.get("profile", False)
        has_syms = entry.get("symbols", False)

        if has_prof and entry.get("note"):
            # Has an explanatory note overriding the stale profile:true — skip
            continue

        if has_prof:
            # Check that at least one profile containing the vendor name exists
            matches = list(PROFILES_DIR.glob(f"{vendor}*.r2"))
            if not matches:
                err(f"coverage.json {key!r}: profile=true but no {vendor}-*.r2 found in profiles/")

        if has_syms:
            sym_vendor_dir = SYMBOLS_DIR / vendor
            if not sym_vendor_dir.exists():
                warn(f"coverage.json {key!r}: symbols=true but symbols/{vendor}/ does not exist")


# ── Check 3: profile zo/to lines reference files that exist ──────────────────

def check_profile_references():
    for profile in sorted(PROFILES_DIR.rglob("*.r2")):
        for lineno, raw in enumerate(profile.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()

            # --- zo lines ---
            if line.startswith("zo ") and not line.startswith("# zo"):
                zsig_rel = line[3:].strip()
                # Strip leading ~/.local/share/radare2/ if present (absolute form)
                zsig_rel = zsig_rel.replace("~/.local/share/radare2/zigns/", "")
                zsig_path = ZIGNS_DIR / zsig_rel
                if not zsig_path.exists():
                    # r2 zo silently skips missing zsig files, so this is a warning
                    # not a hard error. Missing zsigs are expected for planned corpus
                    # expansions (e.g. debian/i386/ before Batch 2 generation runs).
                    warn(f"{profile.relative_to(CORPUS_ROOT)}:{lineno}: zo {zsig_rel!r} ← ZSIG NOT FOUND (run tool/generate-debian-libs-zsig.py to populate)")

            # --- to lines (skip comments, skip absolute paths for types outside corpus) ---
            elif line.startswith("to ") and not line.startswith("# to"):
                type_rel = line[3:].strip()
                if type_rel.startswith("~") or type_rel.startswith("/"):
                    # Absolute path — normalise to relative
                    type_rel = type_rel.replace("~/.local/share/radare2/types/", "")
                    type_rel = type_rel.replace("~/.local/share/radare2/", "")
                type_path = TYPES_DIR / type_rel
                if not type_path.exists():
                    err(f"{profile.relative_to(CORPUS_ROOT)}:{lineno}: to {type_rel!r} ← TYPES FILE NOT FOUND")


# ── Check 4: session zsig index completeness ─────────────────────────────────

def check_session_index():
    if not SESSION_INDEX.exists():
        err(f"session index missing: {SESSION_INDEX}")
        return

    index = json.loads(SESSION_INDEX.read_text())
    sessions_dir = SESSION_INDEX.parent

    # Every .zsig in sessions/ should have an index entry
    for zsig_file in sorted(sessions_dir.glob("*.zsig")):
        key = zsig_file.stem
        if key not in index:
            warn(f"sessions/{zsig_file.name}: no entry in index.json")

    # Every index entry should have a matching .zsig file
    for key, entry in index.items():
        zsig_file = sessions_dir / f"{key}.zsig"
        if not zsig_file.exists():
            err(f"index.json entry {key!r} (binary={entry.get('binary')!r}): .zsig file missing")

    # Quality warnings for low named_pct
    for key, entry in index.items():
        if "named_pct" not in entry:
            # Compute from zsig binary content via strings heuristic
            zsig_file = sessions_dir / f"{key}.zsig"
            if zsig_file.exists():
                import subprocess as _sp
                r = _sp.run(["strings", str(zsig_file)], capture_output=True, text=True)
                total, unnamed = 0, 0
                for line in r.stdout.splitlines():
                    if line.startswith("zign|"):
                        parts = line.split("|", 3)
                        if len(parts) >= 3:
                            total += 1
                            if parts[2].startswith(("fcn.", "sub.")):
                                unnamed += 1
                pct = round((1 - unnamed / max(total, 1)) * 100)
                warn(f"sessions/{key}: missing named_pct in index.json "
                     f"(computed from zsig: {pct}% named, {total} entries) — "
                     f"run corpus_commit.py to persist")
            else:
                warn(f"sessions/{key}: missing named_pct field in index.json")
            continue
        pct = entry.get("named_pct", 100)
        if pct == 0:
            pass   # explicitly zeroed = intentionally archived (all fcn.*, retained for index integrity)
        elif pct < 50:
            warn(f"sessions/{key}.zsig: only {pct}% named functions (consider pruning fcn.* entries)")
        elif pct < 80:
            warn(f"sessions/{key}.zsig: {pct}% named functions (acceptable but pruning fcn.* would help)")


# ── Check 5: zsig directory / profile symmetry ────────────────────────────────

def check_zsig_coverage():
    # Every types/ vendor dir should correspond to at least one profile that loads it
    # Exceptions: directories that intentionally have no headers yet (with README explaining why)
    KNOWN_EMPTY = {
        "embedded",   # DWARF extraction produced void/void sigs — README explains; zsigs exist
    }
    for vendor_dir in sorted(TYPES_DIR.iterdir()):
        if not vendor_dir.is_dir() or vendor_dir.name == "__pycache__":
            continue
        vendor = vendor_dir.name
        if vendor in KNOWN_EMPTY:
            continue
        # Check whether any .h file exists (skip pure-README dirs)
        headers = list(vendor_dir.rglob("*.h"))
        if not headers:
            continue  # nothing to load
        # Check whether any profile loads types from this vendor
        found = False
        for profile in PROFILES_DIR.rglob("*.r2"):
            text = profile.read_text(errors="replace")
            if f"to {vendor}/" in text or f"to ~/.local/share/radare2/types/{vendor}/" in text:
                found = True
                break
        if not found:
            warn(f"types/{vendor}/: no profile loads these types (aaft will be blind)")


# ── Check 6: magic files valid syntax (basic) ─────────────────────────────────

def check_magic_files():
    for mf in sorted(MAGIC_DIR.glob("*.magic")):
        text = mf.read_text(errors="replace")
        lineno = 0
        for raw in text.splitlines():
            lineno += 1
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Basic: first non-comment line of a rule starts with a digit or '>'
            # (continuation lines start with '>')
            # This is a shallow check — just look for obviously broken entries
            if not (line[0].isdigit() or line[0] == ">"):
                warn(f"{mf.name}:{lineno}: unexpected first char {line[0]!r}: {line[:60]}")
                break  # one warning per file is enough


# ── Check 7: dead type headers (exist but no profile loads them) ─────────────

def check_dead_types():
    """Warn about .h files in types/ that no profile references."""
    referenced = set()
    for profile in PROFILES_DIR.rglob("*.r2"):
        for raw in profile.read_text(errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("to ") and not line.startswith("# to"):
                rel = line[3:].strip()
                if rel.startswith("~") or rel.startswith("/"):
                    rel = rel.replace("~/.local/share/radare2/types/", "")
                    rel = rel.replace("~/.local/share/radare2/", "")
                referenced.add(rel)

    for h_file in sorted(TYPES_DIR.rglob("*.h")):
        rel = str(h_file.relative_to(TYPES_DIR))
        if rel not in referenced:
            warn(f"types/{rel}: exists but no profile loads it (dead header)")


# ── Report ────────────────────────────────────────────────────────────────────

def check_arch_defaults():
    """Verify profiles_config.json arch routing is sane.

    Guards against regressions of the Batch 1 bugs:
    - arm/32 with no default (most common embedded arch silently unprovisioned)
    - Windows PE profile as arch default for a Linux/ELF arch
    - High-value libc overrides missing (arm/32/glibc, x86/32/glibc, etc.)
    """
    if not PROFILES_CONFIG.exists():
        return
    cfg = json.loads(PROFILES_CONFIG.read_text())
    arch_profiles = cfg.get("arch_profiles", {})
    libc_profiles  = cfg.get("libc_profiles", {})
    windows_profiles = cfg.get("windows_profiles", {})

    # Rule 1: arm/32 must have a default (most common embedded firmware arch)
    if "arm/32" not in arch_profiles:
        err("profiles_config.json: arch_profiles missing 'arm/32' default — "
            "ARM32 ELF binaries (most embedded firmware) get no types/zsigs")

    # Rule 2: no Linux/ELF arch default should route to a Windows PE profile
    windows_profile_names = set(windows_profiles.values())
    for key, profile_file in arch_profiles.items():
        if profile_file in windows_profile_names:
            err(f"profiles_config.json: arch_profiles[{key!r}] = {profile_file!r} "
                f"routes to a Windows PE profile — Linux ELF binaries get wrong analysis")

    # Rule 3: high-value libc overrides must be present
    HIGH_VALUE_LIBC = [
        ("arm/32/glibc",  "ARM32 glibc firmware (Cobham, Furuno, Intellian, Navico)"),
        ("arm/32/uclibc", "ARM32 uClibc firmware (Supermicro BMC, Buildroot devices)"),
        ("x86/32/glibc",  "Linux i386 glibc firmware (older NAS, routers)"),
        ("x86/64/glibc",  "Linux x86-64 glibc userland (server daemons, CTF)"),
        ("arm/64/glibc",  "AArch64 glibc (Raspberry Pi OS 64-bit, server ARM64)"),
        ("arm/64/uclibc", "AArch64 uClibc (OpenWrt AArch64 targets)"),
    ]
    for key, description in HIGH_VALUE_LIBC:
        if key not in libc_profiles:
            err(f"profiles_config.json: libc_profiles missing {key!r} — "
                f"{description} won't get libc zsigs loaded")
        else:
            profile_file = libc_profiles[key]
            path = PROFILES_DIR / profile_file
            if not path.exists():
                err(f"profiles_config.json: libc_profiles[{key!r}] = {profile_file!r} "
                    f"← FILE NOT FOUND")


def check_orphaned_zsigs():
    """Warn about zsig files not referenced by any profile.

    Exceptions:
    - sessions/   : corpus session zsigs, loaded dynamically by aether_r2profile.py
    - windows/    : large Windows MFC/ATL/vcamp library set; available for manual
                    'zo windows/x64/vs20xx-mfc140.zsig' use; not auto-loaded because
                    most PE targets don't link MFC. See windows-x64.r2 for the
                    auto-loaded subset.
    """
    import re
    all_refs: set[str] = set()
    for profile in PROFILES_DIR.rglob("*.r2"):
        for m in re.finditer(r"^zo\s+(\S+)",
                             profile.read_text(errors="replace"), re.MULTILINE):
            all_refs.add(m.group(1))

    for zsig in sorted(ZIGNS_DIR.rglob("*.zsig")):
        rel = str(zsig.relative_to(ZIGNS_DIR))
        # Intentional exemptions
        if rel.startswith("sessions/"):
            continue
        if rel.startswith("windows/"):
            continue   # manual-use extras; not a corpus quality issue
        if rel not in all_refs:
            size_kb = zsig.stat().st_size // 1024
            warn(f"zsig not referenced by any profile: {rel}  ({size_kb} KB) "
                 f"\u2014 add zo to a profile or document as manual-use")


def main():
    ap = argparse.ArgumentParser(description="Validate r2 corpus consistency")
    ap.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    ap.add_argument("--fix",  action="store_true", help="(reserved) auto-fix trivial issues")
    args = ap.parse_args()

    check_profiles_config()
    check_arch_defaults()
    check_coverage()
    check_profile_references()
    check_session_index()
    check_zsig_coverage()
    check_magic_files()
    check_dead_types()
    check_orphaned_zsigs()

    if args.json:
        print(json.dumps({"errors": ERRORS, "warnings": WARNINGS}, indent=2))
    else:
        width = 78
        if ERRORS:
            print(f"\n{'─'*width}")
            print(f"  ERRORS ({len(ERRORS)})")
            print(f"{'─'*width}")
            for e in ERRORS:
                print(f"  ✗ {e}")
        if WARNINGS:
            print(f"\n{'─'*width}")
            print(f"  WARNINGS ({len(WARNINGS)})")
            print(f"{'─'*width}")
            for w in WARNINGS:
                print(f"  ! {w}")
        if not ERRORS and not WARNINGS:
            print("  ✓ Corpus is consistent — no issues found.")
        else:
            total = len(ERRORS) + len(WARNINGS)
            print(f"\n  {len(ERRORS)} error(s), {len(WARNINGS)} warning(s)  [{total} total]")

    sys.exit(1 if ERRORS else 0)


if __name__ == "__main__":
    main()
