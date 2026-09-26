#!/usr/bin/env python3
"""
Generate r2 zignatures from uClibc-ng static libraries for MIPS big-endian targets.

Downloads Bootlin pre-built toolchains and generates zsig files per CPU profile.
Source libraries: Bootlin uClibc-ng stable toolchains (https://toolchains.bootlin.com)

Usage:
    generate-uclibc-mipsbe-zsig.py --profile mips32
    generate-uclibc-mipsbe-zsig.py --all
    generate-uclibc-mipsbe-zsig.py --list
"""
import argparse
import importlib.util
import sys
from pathlib import Path

from zsig_utils import (
    generate_zsig_from_libc_dir,
    get_zsig_output_dir,
)

SCRIPT_DIR = Path(__file__).parent
_spec = importlib.util.spec_from_file_location(
    "download_uclibc_mipsbe", SCRIPT_DIR / "download-uclibc-mipsbe.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

download_uclibc_mipsbe = _mod.download_uclibc_mipsbe
UCLIBC_PROFILES = _mod.UCLIBC_PROFILES

ZSIG_OUTPUT_DIR = get_zsig_output_dir("uclibc")


def generate_uclibc_mipsbe_zsig(
    profile: str,
    version: str = None,
    output_dir: Path = None,
) -> bool:
    """Generate zsig for one uClibc-ng MIPS BE profile."""
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    _, desc = UCLIBC_PROFILES[profile]
    print(f"\n=== {profile}  ({desc}) ===")

    libs_dir = download_uclibc_mipsbe(profile, version)
    if not libs_dir:
        print(f"  Download failed for {profile}")
        return False

    output_path = output_dir / profile / "uclibc-libc.zsig"
    success, sig_count = generate_zsig_from_libc_dir(
        str(libs_dir),
        str(output_path),
        prefix="uclibc",
        log=print,
    )
    if success:
        size = output_path.stat().st_size
        print(f"\n  Output: {output_path} ({sig_count} sigs, {size:,} bytes)")
    else:
        print("  zsig generation failed")
    return success


def list_available() -> None:
    print("uClibc-ng MIPS big-endian profiles available for zsig generation:")
    print()
    for profile, (arch_dir, desc) in UCLIBC_PROFILES.items():
        print(f"  {profile:<18}  {desc}")
    print()
    print(f"Output directory: {ZSIG_OUTPUT_DIR}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate r2 zignatures from uClibc-ng libc (MIPS big-endian)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --profile mips32
    %(prog)s --profile mips32r5-fp --version 2024.05-1
""",
    )
    parser.add_argument("--list", action="store_true", help="List profiles")
    parser.add_argument("--all", action="store_true", help="Generate for all profiles")
    parser.add_argument("--profile", help=f"CPU profile ({', '.join(UCLIBC_PROFILES)})")
    parser.add_argument("--version", help="Bootlin release tag (discovered if omitted)")
    parser.add_argument("--output-dir", help="Override zsig output directory")
    args = parser.parse_args()

    if args.list:
        list_available()
        return

    output_dir = Path(args.output_dir) if args.output_dir else ZSIG_OUTPUT_DIR

    if args.all:
        ok = sum(
            generate_uclibc_mipsbe_zsig(p, args.version, output_dir)
            for p in UCLIBC_PROFILES
        )
        print(f"\n=== Done: {ok}/{len(UCLIBC_PROFILES)} profiles generated ===")
    elif args.profile:
        if args.profile not in UCLIBC_PROFILES:
            print(f"Unknown profile: {args.profile}", file=sys.stderr)
            print(f"Available: {', '.join(UCLIBC_PROFILES)}", file=sys.stderr)
            sys.exit(1)
        if not generate_uclibc_mipsbe_zsig(args.profile, args.version, output_dir):
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
