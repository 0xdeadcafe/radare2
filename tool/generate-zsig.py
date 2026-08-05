#!/usr/bin/env python3
"""
Generate r2 zignatures from Linux library packages.

This script processes .deb packages containing static libraries with symbols
and generates zsig files for function recognition in stripped binaries.

IMPORTANT: Always use -dev packages with symbols, never stripped system libraries.
           Stripped libraries produce ~10x fewer signature matches.

Requirements:
    - Python 3.8+
    - r2pipe (pip install r2pipe)
    - ar, nm (binutils)

Usage:
    generate-zsig.py --deb libc6-dev_2.35_amd64.deb -o libc6.zsig
    generate-zsig.py --lib /path/to/libfoo.a -o libfoo.zsig
"""
import argparse
import glob
import os
import sys
import tempfile
from pathlib import Path

from zsig_utils import (
    run,
    check_symbols,
    generate_zsig_from_lib,
    merge_zsigs,
    require_tools,
    get_zsig_output_dir,
)


def extract_libs_from_deb(deb_path: str, work_dir: str) -> list[str]:
    """Extract .a files from a .deb package.
    
    Supports xz, zst, gz compression (zst requires zstd installed).
    """
    ar_result = run(["ar", "t", deb_path])
    if ar_result.returncode != 0:
        print(f"  Error: cannot list {deb_path}", file=sys.stderr)
        return []
    
    files = ar_result.stdout.decode().strip().split("\n")
    data_tar = next((f for f in files if f.startswith("data.tar")), None)
    if not data_tar:
        print(f"  Error: no data.tar in {deb_path}", file=sys.stderr)
        return []
    
    # Extract data.tar
    ar_extract = run(["ar", "p", deb_path, data_tar])
    if ar_extract.returncode != 0:
        return []
    
    # Determine compression
    tar_flags = ["-x", "-C", work_dir]
    if data_tar.endswith('.zst'):
        tar_flags.append("--zstd")
    elif data_tar.endswith('.xz'):
        tar_flags.append("--xz")
    elif data_tar.endswith('.gz'):
        tar_flags.append("--gzip")
    elif data_tar.endswith('.bz2'):
        tar_flags.append("--bzip2")
    
    tar_result = run(["tar"] + tar_flags, input=ar_extract.stdout)
    if tar_result.returncode != 0:
        print(f"  Error: tar extraction failed", file=sys.stderr)
        return []
    
    # Find .a files (static libraries with symbols)
    libs = glob.glob(os.path.join(work_dir, "**/*.a"), recursive=True)
    return libs


def process_deb(deb_path: str, output_zsig: str) -> bool:
    """Process a .deb file into a zsig."""
    print(f"Processing: {deb_path}")

    with tempfile.TemporaryDirectory() as work_dir:
        libs = extract_libs_from_deb(deb_path, work_dir)
        if not libs:
            print(f"  No libraries found")
            return False

        print(f"  Found {len(libs)} library files")

        zsig_parts = []
        total_sigs = 0

        for lib in libs:
            lib_name = Path(lib).name

            sym_count = check_symbols(lib)
            if sym_count < 10:
                print(f"  {lib_name}: SKIP (only {sym_count} symbols - stripped?)")
                continue

            print(f"  {lib_name}: {sym_count} symbols...", end=" ", flush=True)

            part_zsig = os.path.join(work_dir, f"{lib_name}.zsig")
            success, sig_count = generate_zsig_from_lib(lib, part_zsig, work_dir)
            if success:
                size = os.path.getsize(part_zsig)
                print(f"OK ({sig_count} sigs, {size:,} bytes)")
                zsig_parts.append(part_zsig)
                total_sigs += sig_count
            else:
                print("FAIL")

        if not zsig_parts:
            print(f"  No zignatures generated")
            return False

        print(f"  Merging {len(zsig_parts)} zsigs...")
        os.makedirs(os.path.dirname(os.path.abspath(output_zsig)), exist_ok=True)

        success, final_count = merge_zsigs(zsig_parts, output_zsig)
        if success:
            size = os.path.getsize(output_zsig)
            print(f"  Output: {output_zsig} ({final_count} sigs, {size:,} bytes)")
            return True
        else:
            print(f"  Merge failed")
            return False


def process_lib(lib_path: str, output_zsig: str) -> bool:
    """Process a single library file into a zsig."""
    print(f"Processing: {lib_path}")

    sym_count = check_symbols(lib_path)
    if sym_count < 10:
        print(f"  WARNING: Only {sym_count} symbols - library may be stripped")
    else:
        print(f"  Symbols: {sym_count}")

    with tempfile.TemporaryDirectory() as work_dir:
        os.makedirs(os.path.dirname(os.path.abspath(output_zsig)), exist_ok=True)
        success, sig_count = generate_zsig_from_lib(lib_path, output_zsig, work_dir)
        if success:
            size = os.path.getsize(output_zsig)
            print(f"  Output: {output_zsig} ({sig_count} sigs, {size:,} bytes)")
            return True
        else:
            print(f"  Failed to generate zsig")
            return False


def main():
    # Check for required tools upfront
    require_tools(["ar", "nm"], install_hint="apt install binutils")
    
    parser = argparse.ArgumentParser(
        description="Generate r2 zignatures from Linux library packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
IMPORTANT: Always use -dev packages with symbols!
           Stripped libraries produce ~10x fewer matches.

Environment variables:
    R2_ZSIG_DIR     Override output directory for zsig files
    R2_DATA_DIR     Base directory for radare2 data (default: ~/.local/share/radare2)

Examples:
    %(prog)s --deb libc6-dev_2.35_amd64.deb -o libc6.zsig
    %(prog)s --lib /path/to/libfoo.a -o libfoo.zsig
        """
    )
    
    parser.add_argument('--deb', type=str, help="Path to .deb package")
    parser.add_argument('--lib', type=str, help="Path to .a library file")
    parser.add_argument('-o', '--output', type=str, required=True, help="Output zsig path")

    args = parser.parse_args()

    if args.deb:
        if not os.path.exists(args.deb):
            print(f"Error: {args.deb} not found", file=sys.stderr)
            sys.exit(1)
        if process_deb(args.deb, args.output):
            print(f"\nSuccess: {args.output}")
        else:
            sys.exit(1)

    elif args.lib:
        if not os.path.exists(args.lib):
            print(f"Error: {args.lib} not found", file=sys.stderr)
            sys.exit(1)
        if process_lib(args.lib, args.output):
            print(f"\nSuccess: {args.output}")
        else:
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
