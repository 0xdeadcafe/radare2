#!/usr/bin/env python3
"""
Download uClibc-ng static libraries from Bootlin pre-built toolchains.

Bootlin (https://toolchains.bootlin.com) ships ready-made GCC/uClibc-ng
cross-compilation toolchains for many embedded targets.  These are built with
Buildroot and include a full musl/uClibc sysroot with static archives.

MIPS big-endian profiles covered:
  mips32          MIPS32r1, soft-float, BE  — classic embedded Linux devices
                  (Atheros AR7, Broadcom BCM5350, old DD-WRT/OpenWrt)
  mips32r5-fp     MIPS32r5, hard-float, BE  — BCM6xxx DSL gateways, AR9xxx
  mips64          MIPS64, N64 ABI, soft-float, BE — Cavium Octeon, SiByte

Requirements:
    - Python 3.8+
    - curl
    - bzip2

Usage:
    download-uclibc-mipsbe.py --list
    download-uclibc-mipsbe.py --all
    download-uclibc-mipsbe.py --profile mips32
    download-uclibc-mipsbe.py --profile mips32 --version 2024.05-1
"""
import argparse
import os
import re
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
DOWNLOAD_DIR = R2_DATA_DIR / "cache" / "uclibc-bootlin"

BOOTLIN_BASE = "https://toolchains.bootlin.com/downloads/releases/toolchains"

# profile -> (bootlin_arch_dir, description)
UCLIBC_PROFILES: dict[str, tuple[str, str]] = {
    "mips32": (
        "mips32",
        "MIPS32r1, soft-float, big-endian — AR7/BCM5350/old Atheros, classic DD-WRT/OpenWrt",
    ),
    "mips64": (
        "mips64",
        "MIPS64, N64 ABI, soft-float, big-endian — Cavium Octeon, SiByte",
    ),
    "mips64-n32": (
        "mips64-n32",
        "MIPS64, N32 ABI, soft-float, big-endian — Octeon III, some BCM1xxx deployments",
    ),
}

# Libraries to extract from the toolchain sysroot
WANTED_LIBS = {
    "libc.a",
    "libm.a",
    "libpthread.a",
    "librt.a",
    "libdl.a",
    "libcrypt.a",
    "libresolv.a",
    "libutil.a",
    "libnsl.a",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch_url(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def discover_tarball(arch_dir: str) -> str | None:
    """Scrape the Bootlin tarballs index to find the latest uClibc-ng stable tarball."""
    url = f"{BOOTLIN_BASE}/{arch_dir}/tarballs/"
    try:
        html = fetch_url(url).decode(errors="replace")
    except Exception as e:
        print(f"  Failed to fetch index {url}: {e}", file=sys.stderr)
        return None

    # Match: {arch}--uclibc--stable-{date}-{rev}.tar.bz2
    pat = re.compile(
        rf'href="({re.escape(arch_dir)}--uclibc--stable-[^"]+\.tar\.bz2)"'
    )
    matches = pat.findall(html)
    if not matches:
        return None
    # Take the last (latest) match
    return matches[-1]


def stream_extract_libs(url: str, dest_dir: Path) -> list[Path]:
    """
    Stream-decompress a .tar.bz2 from url and extract uClibc-ng .a files to dest_dir.

    Pipeline: curl | bzip2 -d | tarfile(r|)
    No full tarball is written to disk — saves ~100-200 MB per profile.

    We accept libc.a etc. from any path matching:
      .../sysroot/lib/{name}  or  .../sysroot/usr/lib/{name}
    and skip GCC's own internal archives (.../lib/gcc/...).
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []

    print(f"  Streaming {url.split('/')[-1]}...", end=" ", flush=True)

    try:
        proc_curl = subprocess.Popen(
            ["curl", "-sL", "--max-time", "300", url],
            stdout=subprocess.PIPE,
        )
        proc_bz2 = subprocess.Popen(
            ["bzip2", "-d", "--stdout"],
            stdin=proc_curl.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        proc_curl.stdout.close()

        with tarfile.open(fileobj=proc_bz2.stdout, mode="r|") as tar:
            for member in tar:
                if not member.isreg():
                    continue
                bname = Path(member.name).name
                if bname not in WANTED_LIBS:
                    continue
                # Skip GCC's own internal archives
                if "/lib/gcc/" in member.name:
                    continue
                # Only pick up sysroot libs, not the GCC host libs
                if "sysroot/lib/" not in member.name and "sysroot/usr/lib/" not in member.name:
                    continue
                fobj = tar.extractfile(member)
                if fobj is None:
                    continue
                dest = dest_dir / bname
                dest.write_bytes(fobj.read())
                extracted.append(dest)

        proc_bz2.wait()
        proc_curl.wait()

        if extracted:
            print(f"OK ({len(extracted)} libs)")
            names = sorted(p.name for p in extracted)
            print(f"    Libs: {', '.join(names[:6])}{'…' if len(names) > 6 else ''}")
        else:
            print("OK (0 libs — check sysroot path in tarball)")

    except Exception as e:
        print(f"FAILED: {e}")

    return extracted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def download_uclibc_mipsbe(
    profile: str,
    version: str = None,
    download_dir: Path = None,
) -> Path | None:
    """
    Download and cache uClibc-ng libs for a MIPS BE profile.

    Args:
        profile: One of the keys in UCLIBC_PROFILES
        version: Bootlin release tag (e.g. "2024.05-1"); discovered if None
        download_dir: Override default cache location

    Returns:
        Path to the libs directory, or None on failure.
    """
    if profile not in UCLIBC_PROFILES:
        print(f"Unknown profile: {profile}", file=sys.stderr)
        print(f"Available: {', '.join(UCLIBC_PROFILES)}", file=sys.stderr)
        return None

    arch_dir, desc = UCLIBC_PROFILES[profile]
    download_dir = download_dir or DOWNLOAD_DIR

    print(f"uClibc-ng {profile}:")
    print(f"  {desc}")

    # Discover tarball filename first (needed to know the version subdir)
    print(f"  Discovering tarball...", end=" ", flush=True)
    filename = discover_tarball(arch_dir)
    if not filename:
        print("FAILED — no uClibc tarball found in Bootlin index")
        return None
    print(filename)

    # If a specific version was requested, verify it matches
    if version and f"stable-{version}" not in filename:
        print(f"  WARNING: requested version {version} not found; using {filename}")

    # Extract the full version tag from the filename for the cache path
    m = re.search(r"--stable-(.+?)\.tar", filename)
    ver_tag = m.group(1) if m else "unknown"

    libs_dir = download_dir / ver_tag / profile / "libs"

    # Already extracted?
    if libs_dir.exists() and list(libs_dir.glob("*.a")):
        count = len(list(libs_dir.glob("*.a")))
        print(f"  Already cached ({count} libs in {libs_dir})")
        return libs_dir

    url = f"{BOOTLIN_BASE}/{arch_dir}/tarballs/{filename}"
    extracted = stream_extract_libs(url, libs_dir)

    if not extracted:
        return None

    return libs_dir


def list_available() -> None:
    print(f"uClibc-ng MIPS big-endian profiles (Bootlin toolchains):")
    print()
    for profile, (arch_dir, desc) in UCLIBC_PROFILES.items():
        print(f"  {profile:<18}  {desc}")
    print()
    print(f"Source:          {BOOTLIN_BASE}/{{arch}}/tarballs/")
    print(f"Cache directory: {DOWNLOAD_DIR}")
    print(f"Override:        --version 2024.05-1")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download uClibc-ng static libraries from Bootlin toolchains (MIPS BE)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --profile mips32
    %(prog)s --profile mips32r5-fp --version 2024.05-1
""",
    )
    parser.add_argument("--list", action="store_true", help="List available profiles")
    parser.add_argument("--all", action="store_true", help="Download all profiles")
    parser.add_argument("--profile", help=f"CPU profile ({', '.join(UCLIBC_PROFILES)})")
    parser.add_argument("--version", help="Bootlin release tag (e.g. 2024.05-1); discovered if omitted")
    parser.add_argument("--output-dir", help="Override cache directory")
    args = parser.parse_args()

    dl_dir = Path(args.output_dir) if args.output_dir else DOWNLOAD_DIR

    if args.list:
        list_available()
        return

    if not args.all and not args.profile:
        parser.print_help()
        return

    print(f"Cache directory: {dl_dir}")
    print()

    profiles = list(UCLIBC_PROFILES) if args.all else [args.profile]
    for p in profiles:
        if p not in UCLIBC_PROFILES:
            print(f"Unknown profile: {p}", file=sys.stderr)
            print(f"Available: {', '.join(UCLIBC_PROFILES)}", file=sys.stderr)
            sys.exit(1)
        result = download_uclibc_mipsbe(p, args.version, dl_dir)
        if result:
            print(f"  Output: {result}")
        print()


if __name__ == "__main__":
    main()
