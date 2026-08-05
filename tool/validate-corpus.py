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
            else:
                ok(f"  ✓ {section}/{key} → {profile_file}")


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
                    err(f"{profile.relative_to(CORPUS_ROOT)}:{lineno}: zo {zsig_rel!r} ← ZSIG NOT FOUND")

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
        if pct < 50:
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

def main():
    ap = argparse.ArgumentParser(description="Validate r2 corpus consistency")
    ap.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    ap.add_argument("--fix",  action="store_true", help="(reserved) auto-fix trivial issues")
    args = ap.parse_args()

    check_profiles_config()
    check_coverage()
    check_profile_references()
    check_session_index()
    check_zsig_coverage()
    check_magic_files()
    check_dead_types()

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
