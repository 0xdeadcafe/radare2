#!/usr/bin/env python3
"""
Download musl libc static libraries from OpenWrt toolchain tarballs.

OpenWrt ships musl built with target-specific CFLAGS (ISA, ABI, FPU) that
differ from generic musl builds.  These signatures therefore match firmware
you'd pull from a real router more accurately than Alpine's generic musl.

Sources: https://downloads.openwrt.org/releases/<version>/targets/<t>/<sub>/

CPU profiles covered:
  mips_24kc        ath79/generic   Atheros AR7xxx/AR9xxx, BE  (most SOHO routers)
  mipsel_24kc      ramips/mt7621   MediaTek MT7620/MT7621, LE (Xiaomi, ASUS, TP-Link)
  mipsel_mips32    bcm47xx/generic Broadcom BCM47xx, LE       (legacy Linksys/Netgear)
  mips_mips32      bmips/bcm6358   Broadcom BCM63xx, BE       (xDSL gateways)
  mips64_octeonplus octeon/generic Cavium Octeon, 64-bit BE   (EdgeRouter, carrier)

Requirements:
    - Python 3.8+
    - zstd  (CLI decompressor, usually packaged as zstd)
    - tar

Usage:
    download-openwrt-musl.py --list
    download-openwrt-musl.py --all
    download-openwrt-musl.py --profile mips_24kc
    download-openwrt-musl.py --profile mips_24kc --version 24.10.6
"""
import argparse
import os
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
DOWNLOAD_DIR = R2_DATA_DIR / "cache" / "openwrt-musl"

OPENWRT_BASE = "https://downloads.openwrt.org/releases"
OPENWRT_VERSION = "24.10.6"

# cpu_profile -> (target, subtarget, description)
# cpu_profile is the name used inside the toolchain dir and as our output key.
OPENWRT_TARGETS: dict[str, tuple[str, str, str]] = {
    "mips_24kc": (
        "ath79", "generic",
        "Atheros AR7xxx/AR9xxx, big-endian — TP-Link WR841N, WR1043ND, GL-AR150, …",
    ),
    "mipsel_24kc": (
        "ramips", "mt7621",
        "MediaTek MT7620/MT7621, little-endian — Xiaomi MiWiFi 3, ASUS RT-N56U, …",
    ),
    "mipsel_mips32": (
        "bcm47xx", "generic",
        "Broadcom BCM47xx, little-endian — Linksys WRT54G, Netgear WGR614, …",
    ),
    "mips_mips32": (
        "bmips", "bcm6358",
        "Broadcom BCM63xx, big-endian — Livebox 2, HomeHub 2B, BT HH3, …",
    ),
    "mips64_octeonplus": (
        "octeon", "generic",
        "Cavium Octeon, 64-bit big-endian — Ubiquiti EdgeRouter Lite/4, …",
    ),
}

# Static libraries we want from the toolchain
WANTED_LIBS = {
    "libc.a", "libm.a", "libpthread.a", "librt.a",
    "libdl.a", "libcrypt.a", "libresolv.a", "libutil.a", "libxnet.a",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch_url(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def discover_toolchain_filename(version: str, target: str, subtarget: str) -> str | None:
    """Scrape the OpenWrt index page to find the toolchain .tar.zst filename."""
    url = f"{OPENWRT_BASE}/{version}/targets/{target}/{subtarget}/"
    try:
        html = fetch_url(url).decode(errors="replace")
    except Exception as e:
        print(f"  Failed to fetch index {url}: {e}", file=sys.stderr)
        return None

    # Match: openwrt-toolchain-<ver>-<target>-<subtarget>_gcc-..._musl.Linux-x86_64.tar.zst
    import re
    pat = re.compile(
        r'href="(openwrt-toolchain-[^"]+_musl\.Linux-x86_64\.tar\.zst)"'
    )
    m = pat.search(html)
    return m.group(1) if m else None


def stream_extract_libs(url: str, dest_dir: Path) -> list[Path]:
    """
    Stream-decompress a .tar.zst from url and extract musl .a files to dest_dir.

    Uses: curl | zstd -d --stdout | tarfile (streaming mode 'r|')
    No full-tarball temp file needed — saves ~44 MB per arch.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []

    print(f"  Streaming {url.split('/')[-1]}...", end=" ", flush=True)

    try:
        proc_curl = subprocess.Popen(
            ["curl", "-sL", "--max-time", "300", url],
            stdout=subprocess.PIPE,
        )
        proc_zstd = subprocess.Popen(
            ["zstd", "-d", "--stdout"],
            stdin=proc_curl.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        proc_curl.stdout.close()  # allow curl to receive SIGPIPE if zstd dies

        with tarfile.open(fileobj=proc_zstd.stdout, mode="r|") as tar:
            for member in tar:
                if not member.isreg():
                    continue
                bname = Path(member.name).name
                # Only grab musl sysroot libs, not GCC's own archives
                if bname not in WANTED_LIBS:
                    continue
                # Confirm it's in the musl sysroot (not GCC's lib/gcc/... subtree)
                if "/lib/gcc/" in member.name:
                    continue
                fobj = tar.extractfile(member)
                if fobj is None:
                    continue
                dest = dest_dir / bname
                dest.write_bytes(fobj.read())
                extracted.append(dest)

        proc_zstd.wait()
        proc_curl.wait()

        print(f"OK ({len(extracted)} libs)")
        if extracted:
            names = sorted(p.name for p in extracted)
            print(f"    Libs: {', '.join(names[:6])}{'…' if len(names) > 6 else ''}")

    except Exception as e:
        print(f"FAILED: {e}")

    return extracted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def download_openwrt_musl(
    profile: str,
    version: str = None,
    download_dir: Path = None,
) -> Path | None:
    """
    Download and cache musl libs for an OpenWrt CPU profile.

    Returns path to the libs directory, or None on failure.
    """
    if profile not in OPENWRT_TARGETS:
        print(f"Unknown profile: {profile}", file=sys.stderr)
        print(f"Available: {', '.join(OPENWRT_TARGETS)}", file=sys.stderr)
        return None

    version = version or OPENWRT_VERSION
    download_dir = download_dir or DOWNLOAD_DIR
    target, subtarget, desc = OPENWRT_TARGETS[profile]

    print(f"OpenWrt {profile} (v{version}):")
    print(f"  {desc}")

    libs_dir = download_dir / version / profile / "libs"

    # Already extracted?
    if libs_dir.exists() and list(libs_dir.glob("*.a")):
        count = len(list(libs_dir.glob("*.a")))
        print(f"  Already cached ({count} libs)")
        return libs_dir

    # Discover filename dynamically (GCC version may change across OpenWrt releases)
    print(f"  Discovering toolchain filename...", end=" ", flush=True)
    filename = discover_toolchain_filename(version, target, subtarget)
    if not filename:
        print("FAILED — could not find toolchain in index")
        return None
    print(filename)

    url = f"{OPENWRT_BASE}/{version}/targets/{target}/{subtarget}/{filename}"
    extracted = stream_extract_libs(url, libs_dir)

    return libs_dir if extracted else None


def list_available() -> None:
    print(f"OpenWrt musl CPU profiles (release {OPENWRT_VERSION}):")
    print()
    for profile, (target, subtarget, desc) in OPENWRT_TARGETS.items():
        print(f"  {profile:<22}  {target}/{subtarget}")
        print(f"    {desc}")
    print()
    print(f"Cache directory: {DOWNLOAD_DIR}")
    print(f"Override release: --version X.Y.Z")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download OpenWrt musl libc static libraries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --profile mips_24kc
    %(prog)s --profile mipsel_24kc --version 24.10.6
""",
    )
    parser.add_argument("--list", action="store_true", help="List available CPU profiles")
    parser.add_argument("--all", action="store_true", help="Download all profiles")
    parser.add_argument("--profile", help=f"CPU profile ({', '.join(OPENWRT_TARGETS)})")
    parser.add_argument("--version", default=OPENWRT_VERSION, help="OpenWrt release version")
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

    profiles = list(OPENWRT_TARGETS) if args.all else [args.profile]
    for p in profiles:
        result = download_openwrt_musl(p, args.version, dl_dir)
        if result:
            print(f"  Output: {result}")
        print()


if __name__ == "__main__":
    main()
