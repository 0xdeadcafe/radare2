#!/usr/bin/env python3
"""
Generate r2 zignatures from OpenWrt musl libc static libraries.

Downloads OpenWrt toolchain tarballs and generates zsig files for
target-specific musl builds (mips_24kc, mipsel_24kc, etc.).

Usage:
    generate-openwrt-musl-zsig.py --profile mips_24kc
    generate-openwrt-musl-zsig.py --all
    generate-openwrt-musl-zsig.py --list
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
_spec = importlib.util.spec_from_file_location(
    "download_openwrt_musl", SCRIPT_DIR / "download-openwrt-musl.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

download_openwrt_musl = _mod.download_openwrt_musl
OPENWRT_TARGETS = _mod.OPENWRT_TARGETS
OPENWRT_VERSION = _mod.OPENWRT_VERSION

ZSIG_OUTPUT_DIR = get_zsig_output_dir("openwrt")


def generate_openwrt_musl_zsig(
    profile: str,
    version: str = None,
    output_dir: Path = None,
) -> bool:
    """Generate zsig for one OpenWrt CPU profile."""
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    version = version or OPENWRT_VERSION

    _, _, desc = OPENWRT_TARGETS[profile]
    print(f"\n=== {profile}  ({desc}) ===")

    libs_dir = download_openwrt_musl(profile, version)
    if not libs_dir:
        print(f"  Download failed for {profile}")
        return False

    output_path = output_dir / profile / "musl-libc.zsig"
    success, sig_count = generate_zsig_from_libc_dir(
        str(libs_dir),
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
    print("OpenWrt musl CPU profiles available for zsig generation:")
    print()
    for profile, (target, subtarget, desc) in OPENWRT_TARGETS.items():
        print(f"  {profile:<22}  {target}/{subtarget}")
        print(f"    {desc}")
    print()
    print(f"Output directory: {ZSIG_OUTPUT_DIR}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate r2 zignatures from OpenWrt musl libc",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --profile mips_24kc
    %(prog)s --profile mipsel_24kc --version 24.10.6
""",
    )
    parser.add_argument("--list", action="store_true", help="List CPU profiles")
    parser.add_argument("--all", action="store_true", help="Generate for all profiles")
    parser.add_argument("--profile", help=f"CPU profile ({', '.join(OPENWRT_TARGETS)})")
    parser.add_argument("--version", default=OPENWRT_VERSION, help="OpenWrt release version")
    parser.add_argument("--output-dir", help="Override zsig output directory")
    args = parser.parse_args()

    if args.list:
        list_available()
        return

    output_dir = Path(args.output_dir) if args.output_dir else ZSIG_OUTPUT_DIR

    if args.all:
        ok = sum(
            generate_openwrt_musl_zsig(p, args.version, output_dir)
            for p in OPENWRT_TARGETS
        )
        print(f"\n=== Done: {ok}/{len(OPENWRT_TARGETS)} profiles generated ===")
    elif args.profile:
        if args.profile not in OPENWRT_TARGETS:
            print(f"Unknown profile: {args.profile}", file=sys.stderr)
            print(f"Available: {', '.join(OPENWRT_TARGETS)}", file=sys.stderr)
            sys.exit(1)
        if not generate_openwrt_musl_zsig(args.profile, args.version, output_dir):
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
