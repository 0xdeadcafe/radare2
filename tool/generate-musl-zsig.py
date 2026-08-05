#!/usr/bin/env python3
"""
Generate r2 zignatures from musl libc static libraries.

Downloads musl-dev packages from Alpine Linux and generates zsig files.

Usage:
    generate-musl-zsig.py --arch x86_64
    generate-musl-zsig.py --all
    generate-musl-zsig.py --list
"""
import argparse
import sys
from pathlib import Path

from zsig_utils import (
    generate_zsig_from_libc_dir,
    get_zsig_output_dir,
)

import importlib.util
SCRIPT_DIR = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("download_musl", SCRIPT_DIR / "download-musl.py")
_download_musl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_download_musl)
download_musl = _download_musl.download_musl
ARCH_MAP = _download_musl.ARCH_MAP

ZSIG_OUTPUT_DIR = get_zsig_output_dir("musl")


def generate_musl_zsig(arch: str, output_dir: Path = None) -> bool:
    """Generate zsig for a musl architecture."""
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    print(f"\n=== Generating musl zsig for {arch} ===")

    lib_dir = download_musl(arch)
    if not lib_dir:
        print(f"Failed to download musl-dev for {arch}")
        return False

    output_path = output_dir / arch / "musl-libc.zsig"
    success, sig_count = generate_zsig_from_libc_dir(
        str(lib_dir),
        str(output_path),
        prefix="musl",
        log=print,
    )
    if success:
        size = output_path.stat().st_size
        print(f"\n  Output: {output_path} ({sig_count} sigs, {size:,} bytes)")
    else:
        print("  zsig generation failed")
    return success


def list_available() -> None:
    print("Available musl architectures:")
    print()
    for arch in ARCH_MAP:
        print(f"  {arch}")
    print()
    print(f"Output directory: {ZSIG_OUTPUT_DIR}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate r2 zignatures from musl libc",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --arch x86_64       # Generate for x86_64
    %(prog)s --all               # Generate for all architectures
    %(prog)s --list              # List available architectures
""",
    )
    parser.add_argument("--list", action="store_true", help="List available architectures")
    parser.add_argument("--all", action="store_true", help="Generate for all architectures")
    parser.add_argument("--arch", type=str, help=f"Architecture ({', '.join(ARCH_MAP.keys())})")
    parser.add_argument("--output-dir", type=str, help="Output directory (overrides default)")
    args = parser.parse_args()

    if args.list:
        list_available()
        return

    output_dir = Path(args.output_dir) if args.output_dir else ZSIG_OUTPUT_DIR

    if args.all:
        ok = sum(generate_musl_zsig(arch, output_dir) for arch in ARCH_MAP)
        print(f"\n=== Generated {ok}/{len(ARCH_MAP)} zsigs ===")
    elif args.arch:
        if args.arch not in ARCH_MAP:
            print(f"Unknown architecture: {args.arch}", file=sys.stderr)
            print(f"Available: {', '.join(ARCH_MAP.keys())}", file=sys.stderr)
            sys.exit(1)
        if not generate_musl_zsig(args.arch, output_dir):
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
