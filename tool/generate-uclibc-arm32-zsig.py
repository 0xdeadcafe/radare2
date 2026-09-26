#!/usr/bin/env python3
"""
Generate r2 zignatures from uClibc-ng static libraries for ARM targets.

Downloads Bootlin pre-built toolchains and generates zsig files per CPU profile.
Source libraries: Bootlin uClibc-ng stable toolchains (https://toolchains.bootlin.com)

ARM profiles covered:
  armv5-eabi     ARM926EJ-S class (ARMv5TE, soft-float, EABI)
                 Supermicro BMC, older embedded Linux (ADC, ASP, surveillance cameras)
  armv7-eabihf   Cortex-A7/A8/A9/A15 (ARMv7-A, hard-float, EABI-HF)
                 OpenWrt ARM, newer embedded appliances

Usage:
    generate-uclibc-arm32-zsig.py --list
    generate-uclibc-arm32-zsig.py --all
    generate-uclibc-arm32-zsig.py --profile armv5-eabi
    generate-uclibc-arm32-zsig.py --profile armv7-eabihf --version 2024.02-1
"""
import argparse
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

from zsig_utils import generate_zsig_from_libc_dir, get_zsig_output_dir

SCRIPT_DIR = Path(__file__).parent
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
DOWNLOAD_CACHE = R2_DATA_DIR / "cache" / "uclibc-bootlin-arm"
ZSIG_OUTPUT_DIR = get_zsig_output_dir("uclibc")

BOOTLIN_BASE = "https://toolchains.bootlin.com/downloads/releases/toolchains"

# (bootlin_arch_dir, description, r2_subdir)
ARM_PROFILES: dict[str, tuple[str, str, str]] = {
    "armv5-eabi": (
        "armv5-eabi",
        "ARMv5TE soft-float EABI — ARM926EJ-S, Supermicro BMC, old surveillance cameras",
        "arm32",
    ),
    "armv7-eabihf": (
        "armv7-eabihf",
        "ARMv7-A hard-float EABI-HF — Cortex-A7/A8/A9, OpenWrt ARM, newer appliances",
        "arm32hf",
    ),
}


def _find_latest_stable(arch_dir: str) -> str | None:
    """Discover latest stable toolchain version from Bootlin index."""
    url = f"{BOOTLIN_BASE}/{arch_dir}/tarballs/"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            html = resp.read().decode(errors="replace")
    except Exception as exc:
        print(f"  Cannot fetch Bootlin index: {exc}", file=sys.stderr)
        return None
    import re
    # Match: armv5-eabi--uclibc--stable-2024.02-1.tar.bz2
    pattern = rf"{re.escape(arch_dir)}--uclibc--stable-([\d.]+(?:-\d+)?)\.tar\.bz2"
    versions = re.findall(pattern, html)
    if not versions:
        return None
    # Sort by version string; last unique wins
    versions = sorted(set(versions))
    return versions[-1]


def _download_toolchain(arch_dir: str, version: str | None) -> Path | None:
    """Download Bootlin toolchain tarball; returns path to tarball."""
    if version is None:
        print(f"  Discovering latest stable version for {arch_dir} ...")
        version = _find_latest_stable(arch_dir)
        if version is None:
            print(f"  Cannot determine version for {arch_dir}", file=sys.stderr)
            return None
        print(f"  Found version: {version}")

    tarball_name = f"{arch_dir}--uclibc--stable-{version}.tar.bz2"
    tarball_path = DOWNLOAD_CACHE / tarball_name
    DOWNLOAD_CACHE.mkdir(parents=True, exist_ok=True)

    if tarball_path.exists():
        print(f"  Using cached: {tarball_path}")
        return tarball_path

    url = f"{BOOTLIN_BASE}/{arch_dir}/tarballs/{tarball_name}"
    print(f"  Downloading {url} ...")
    try:
        urllib.request.urlretrieve(url, tarball_path)
    except Exception as exc:
        print(f"  Download failed: {exc}", file=sys.stderr)
        if tarball_path.exists():
            tarball_path.unlink()
        return None
    print(f"  Saved to {tarball_path} ({tarball_path.stat().st_size:,} bytes)")
    return tarball_path


def _extract_uclibc_libs(tarball_path: Path, arch_dir: str) -> Path | None:
    """Extract uClibc static libraries from Bootlin toolchain tarball."""
    extract_dir = DOWNLOAD_CACHE / f"extracted-{arch_dir}"
    libs_dir = extract_dir / "libs"
    libs_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Extracting uClibc .a files from {tarball_path.name} ...")
    extracted = 0
    try:
        with tarfile.open(tarball_path, "r:bz2") as tf:
            for member in tf.getmembers():
                name = member.name
                # Extract only static libs from the sysroot usr/lib directory
                if (name.endswith(".a") and "/sysroot/usr/lib/" in name
                        and not "/usr/lib/gcc/" in name):
                    basename = Path(name).name
                    dest = libs_dir / basename
                    if dest.exists():
                        continue
                    f = tf.extractfile(member)
                    if f:
                        dest.write_bytes(f.read())
                        extracted += 1
    except Exception as exc:
        print(f"  Extraction error: {exc}", file=sys.stderr)
        return None

    if extracted == 0:
        print(f"  No .a files found in {tarball_path.name}", file=sys.stderr)
        return None

    print(f"  Extracted {extracted} .a files to {libs_dir}")
    return libs_dir


def generate_uclibc_arm32_zsig(
    profile: str,
    version: str | None = None,
    output_dir: Path | None = None,
) -> bool:
    """Generate zsig for one uClibc-ng ARM profile."""
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    arch_dir, desc, r2_subdir = ARM_PROFILES[profile]
    print(f"\n=== {profile}  ({desc}) ===")

    tarball = _download_toolchain(arch_dir, version)
    if not tarball:
        return False

    libs_dir = _extract_uclibc_libs(tarball, arch_dir)
    if not libs_dir:
        return False

    output_path = output_dir / r2_subdir / "uclibc-libc.zsig"
    output_path.parent.mkdir(parents=True, exist_ok=True)

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
    print("uClibc-ng ARM profiles available for zsig generation:")
    print()
    for profile, (arch_dir, desc, r2_subdir) in ARM_PROFILES.items():
        print(f"  {profile:<18}  {desc}")
        print(f"  {'':18}  → zigns/uclibc/{r2_subdir}/uclibc-libc.zsig")
    print()
    print(f"Output directory: {ZSIG_OUTPUT_DIR}")
    print(f"Download cache:   {DOWNLOAD_CACHE}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate r2 zignatures from uClibc-ng libc (ARM)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --profile armv5-eabi
    %(prog)s --profile armv5-eabi --version 2024.02-1
    %(prog)s --profile armv7-eabihf --output-dir /tmp/test-zsigs
""",
    )
    parser.add_argument("--list", action="store_true", help="List available ARM profiles")
    parser.add_argument("--all", action="store_true", help="Generate zsigs for all ARM profiles")
    parser.add_argument("--profile", choices=list(ARM_PROFILES.keys()), help="ARM CPU profile")
    parser.add_argument("--version", help="Bootlin release tag (e.g. 2024.02-1); auto-discovered if omitted")
    parser.add_argument("--output-dir", help=f"Override zsig output directory (default: {ZSIG_OUTPUT_DIR})")
    args = parser.parse_args()

    if args.list:
        list_available()
        return

    output_dir = Path(args.output_dir) if args.output_dir else ZSIG_OUTPUT_DIR

    if args.all:
        ok = sum(
            generate_uclibc_arm32_zsig(p, args.version, output_dir)
            for p in ARM_PROFILES
        )
        print(f"\n=== Done: {ok}/{len(ARM_PROFILES)} profiles generated ===")
    elif args.profile:
        if not generate_uclibc_arm32_zsig(args.profile, args.version, output_dir):
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
