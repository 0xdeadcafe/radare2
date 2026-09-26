#!/usr/bin/env python3
"""generate-juniper-zsig.py — Convert Juniper JunOS sigdb.json to r2 .zsig

The sigdb.json format (from zigns/juniper/junos-kmd-21.3-sigdb.json) stores
function signatures extracted from JunOS kmd with a specific MIPS mask applied:
  - sig_len:          byte length of each signature (e.g. 48)
  - mask_description: human-readable description of which bytes are zeroed
  - signatures:       list of {name, masked_bytes (hex), addr_in_kmd}

The mask_description "gp_imm16_zeroed_at_bytes_2-3_and_6-7" means:
  In every 8-byte group (two big-endian MIPS-32 instructions), bytes at
  offsets 2,3 (imm16 of first instruction) and 6,7 (imm16 of second) are
  zeroed in masked_bytes.  The reconstructed mask is therefore:
    ff ff 00 00 ff ff 00 00   (repeated for sig_len / 8 groups)

This is the GP-load masking used by IDA/BinDiff on MIPS binaries and maps
directly to r2's byte+mask zignature format (za name b <bytes> m <mask>).

Usage:
    python3 generate-juniper-zsig.py \\
        zigns/juniper/junos-kmd-21.3-sigdb.json \\
        -o zigns/juniper/junos-kmd-21.3.zsig

    # Dry-run: print first N entries as r2 za commands
    python3 generate-juniper-zsig.py sigdb.json --dry-run --limit 5

Requirements:
    r2pipe  (pip install r2pipe)
"""

import argparse
import json
import os
import re
import sys
import tempfile

try:
    import r2pipe
except ImportError:
    sys.exit("r2pipe not installed: pip install r2pipe")


# ── Mask derivation ───────────────────────────────────────────────────────────

def derive_mask(mask_description: str, sig_len: int) -> str:
    """Derive the hex mask string from the sigdb mask_description field.

    Supported descriptions (only one in practice):
      gp_imm16_zeroed_at_bytes_2-3_and_6-7
        → ff ff 00 00 ff ff 00 00  per 8-byte group

    Returns a hex string of length sig_len * 2.
    Falls back to all-ff (no masking) on unrecognised descriptions.
    """
    desc = mask_description.lower()

    # Parse "zeroed_at_bytes_X-Y_and_P-Q" style descriptions.
    # Match both the initial "at_bytes_N-M" and continuation "and_N-M" clauses.
    zeroed_positions = set()
    for m in re.finditer(r'(?:at_bytes|and)_?(\d+)-(\d+)', desc):
        lo, hi = int(m.group(1)), int(m.group(2))
        zeroed_positions.update(range(lo, hi + 1))

    if zeroed_positions:
        # Build a repeating template of length lcm(group_size)
        # Detect group size: highest zeroed byte + 1 rounded to next power of 2
        group_size = max(8, max(zeroed_positions) + 1)
        # Round up to nearest power of 2 for clean repetition
        g = 1
        while g < group_size:
            g <<= 1
        group_size = g

        template = bytearray()
        for i in range(group_size):
            template.append(0x00 if i in zeroed_positions else 0xFF)

        # Tile template to cover sig_len bytes
        mask_bytes = bytearray()
        while len(mask_bytes) < sig_len:
            mask_bytes += template
        return mask_bytes[:sig_len].hex()

    # Fallback: no masking
    return "ff" * sig_len


# ── Main conversion ───────────────────────────────────────────────────────────

def convert(sigdb_path: str, output_path: str, dry_run: bool = False,
            limit: int = 0, quiet: bool = False) -> int:
    """Convert sigdb.json → .zsig.  Returns count of signatures written."""

    with open(sigdb_path) as fh:
        db = json.load(fh)

    sig_len    = db["sig_len"]
    mask_desc  = db.get("mask_description", "")
    signatures = db["signatures"]

    if limit:
        signatures = signatures[:limit]

    mask_hex = derive_mask(mask_desc, sig_len)

    if not quiet:
        print(f"sigdb: {len(db['signatures'])} signatures, sig_len={sig_len}")
        print(f"mask_description: {mask_desc}")
        print(f"derived mask ({sig_len} bytes): {mask_hex[:32]}...")

    if dry_run:
        for sig in signatures:
            name  = sig["name"].replace(" ", "_").replace("[...]", "_trunc")
            bytes_hex = sig["masked_bytes"]
            print(f"za {name} b {bytes_hex}")
            print(f"za {name} m {mask_hex}")
        return len(signatures)

    # Open a minimal r2 session on a malloc buffer (no real binary needed)
    if not quiet:
        print("Opening r2 session (malloc://1) for zsig generation...")

    r2 = r2pipe.open("malloc://1", flags=["-2"])  # -2 = silence stderr

    written = 0
    errors  = 0
    for i, sig in enumerate(signatures):
        raw_name  = sig["name"]
        # Sanitise: replace spaces, truncation markers, special chars
        name = re.sub(r'[^\w]', '_', raw_name).strip('_')
        if not name:
            name = f"junos_fcn_{i:04x}"

        bytes_hex = sig["masked_bytes"]

        # Validate hex lengths match
        if len(bytes_hex) != sig_len * 2:
            if not quiet:
                print(f"  SKIP {name}: bytes len {len(bytes_hex)} != {sig_len * 2}", file=sys.stderr)
            errors += 1
            continue

        r2.cmd(f"za {name} b {bytes_hex}")
        r2.cmd(f"za {name} m {mask_hex}")
        written += 1

        if not quiet and (i + 1) % 500 == 0:
            print(f"  {i + 1}/{len(signatures)} processed...")

    # Save
    if not quiet:
        print(f"Saving {written} signatures → {output_path}")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    r2.cmd(f"zos {output_path}")
    r2.quit()

    if not quiet:
        if errors:
            print(f"  {errors} signatures skipped (malformed bytes field)")
        print(f"Done: {written} signatures written.")

    return written


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Convert Juniper JunOS sigdb.json to r2 .zsig",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("sigdb",        help="Path to junos-kmd-*.sigdb.json")
    ap.add_argument("-o", "--out",  default=None,
                    help="Output .zsig path (default: next to sigdb, same stem)")
    ap.add_argument("--dry-run",    action="store_true",
                    help="Print za commands instead of writing .zsig")
    ap.add_argument("--limit",      type=int, default=0,
                    help="Process only first N signatures (for testing)")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.sigdb):
        sys.exit(f"ERROR: sigdb file not found: {args.sigdb}")

    out = args.out
    if not out and not args.dry_run:
        stem = re.sub(r'-sigdb\.json$|\.json$', '', args.sigdb)
        out  = stem + ".zsig"

    n = convert(args.sigdb, out, dry_run=args.dry_run,
                limit=args.limit, quiet=args.quiet)
    print(f"{n} signature(s) {'printed' if args.dry_run else 'written'}.")


if __name__ == "__main__":
    main()
