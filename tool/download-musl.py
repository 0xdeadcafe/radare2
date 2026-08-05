#!/usr/bin/env python3
"""
Download musl libc static libraries from Alpine Linux for zsig generation.

This script downloads musl-dev packages from Alpine Linux mirrors and extracts
the static libraries (libc.a, libm.a, etc.) for signature generation.

Requirements:
    - Python 3.8+
    - tar with gzip support (for extracting .apk files)

Usage:
    download-musl.py --list              # Show available musl versions/architectures
    download-musl.py --all               # Download latest musl for all archs
    download-musl.py --arch x86_64       # Download specific arch
    download-musl.py --version 1.2.5-r21 # Download specific version
"""
import argparse
import gzip
import io
import os
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

# Default to ~/.local/share/radare2 for XDG compliance
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
DOWNLOAD_DIR = R2_DATA_DIR / "cache" / "musl"

# Alpine Linux mirror
ALPINE_MIRROR = "https://dl-cdn.alpinelinux.org/alpine"
ALPINE_BRANCH = "latest-stable"

# Architecture mapping (Alpine name -> our name for consistency)
# Alpine uses slightly different names than we might want in output
ARCH_MAP = {
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "armv7": "arm",
    "armhf": "armhf",
    "x86": "i386",
    "ppc64le": "ppc64le",
    "s390x": "s390x",
    "riscv64": "riscv64",
}

# Static libraries we want to extract from musl-dev
WANTED_LIBS = [
    "libc.a",           # Main C library
    "libm.a",           # Math library
    "libpthread.a",     # POSIX threads
    "librt.a",          # Realtime extensions
    "libdl.a",          # Dynamic linking
    "libcrypt.a",       # Cryptographic functions
    "libresolv.a",      # DNS resolver
    "libutil.a",        # Utility functions
    "libxnet.a",        # X/Open networking
]


def fetch_url(url: str, timeout: int = 30) -> bytes:
    """Fetch content from URL."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def parse_apkindex(index_data: bytes) -> dict:
    """Parse APKINDEX content to extract package info.
    
    APKINDEX format is newline-separated records with fields:
    P:package-name
    V:version
    A:architecture
    (blank line between records)
    """
    packages = {}
    current = {}
    
    # APKINDEX is gzipped
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(index_data)) as gz:
            # It's a tarball containing APKINDEX file
            with tarfile.open(fileobj=io.BytesIO(gz.read()), mode='r') as tar:
                for member in tar.getmembers():
                    if member.name == 'APKINDEX':
                        f = tar.extractfile(member)
                        content = f.read().decode('utf-8')
                        break
                else:
                    return packages
    except Exception:
        # Maybe it's just gzipped text, not tarball
        try:
            content = gzip.decompress(index_data).decode('utf-8')
        except Exception:
            content = index_data.decode('utf-8')
    
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            # End of record
            if 'P' in current and 'V' in current:
                packages[current['P']] = current
            current = {}
        elif ':' in line:
            key, value = line.split(':', 1)
            current[key] = value
    
    # Don't forget last record
    if 'P' in current and 'V' in current:
        packages[current['P']] = current
    
    return packages


def get_musl_version(arch: str) -> tuple[str, str] | None:
    """Get latest musl-dev version for an architecture.
    
    Returns (version, filename) tuple or None.
    """
    index_url = f"{ALPINE_MIRROR}/{ALPINE_BRANCH}/main/{arch}/APKINDEX.tar.gz"
    
    try:
        print(f"  Fetching package index for {arch}...", end=" ", flush=True)
        index_data = fetch_url(index_url)
        packages = parse_apkindex(index_data)
        
        if 'musl-dev' not in packages:
            print("musl-dev not found")
            return None
        
        version = packages['musl-dev']['V']
        filename = f"musl-dev-{version}.apk"
        print(f"v{version}")
        return version, filename
        
    except Exception as e:
        print(f"FAILED: {e}")
        return None


def download_apk(arch: str, filename: str, dest_path: Path) -> bool:
    """Download an Alpine package."""
    url = f"{ALPINE_MIRROR}/{ALPINE_BRANCH}/main/{arch}/{filename}"
    print(f"  Downloading {filename}...", end=" ", flush=True)
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as response:
            total_size = response.getheader("Content-Length")
            total_size = int(total_size) if total_size else None
            
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(dest_path, "wb") as f:
                downloaded = 0
                block_size = 8192
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    f.write(buffer)
                    downloaded += len(buffer)
                    if total_size:
                        pct = downloaded * 100 // total_size
                        print(f"\r  Downloading {filename}... {pct}%", end="", flush=True)
            
            print(f"\r  Downloading {filename}... OK ({downloaded:,} bytes)")
            return True
            
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def extract_libs(apk_path: Path, output_dir: Path) -> list[Path]:
    """Extract static libraries from an Alpine package.
    
    Alpine .apk files are gzipped tarballs with structure:
    - .SIGN.* (signature files)
    - .PKGINFO (package metadata)
    - Files at their installed paths (e.g., usr/lib/libc.a)
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_libs = []
    
    print(f"  Extracting libs...", end=" ", flush=True)
    
    try:
        with gzip.open(apk_path, 'rb') as gz:
            with tarfile.open(fileobj=gz, mode='r') as tar:
                for member in tar.getmembers():
                    # Look for .a files in usr/lib/
                    if member.name.endswith('.a') and '/lib/' in member.name:
                        lib_name = os.path.basename(member.name)
                        
                        # Extract wanted libs (or all if you prefer)
                        if lib_name in WANTED_LIBS or lib_name.startswith('lib'):
                            dest_file = output_dir / lib_name
                            
                            # Extract file
                            with tar.extractfile(member) as src:
                                with open(dest_file, 'wb') as dst:
                                    dst.write(src.read())
                            extracted_libs.append(dest_file)
        
        print(f"OK ({len(extracted_libs)} .a files)")
        
        # List the libs found
        if extracted_libs:
            lib_names = sorted([l.name for l in extracted_libs])
            print(f"    Libs: {', '.join(lib_names[:5])}{'...' if len(lib_names) > 5 else ''}")
        
    except Exception as e:
        print(f"FAILED: {e}")
    
    return extracted_libs


def download_musl(arch: str, version: str = None, download_dir: Path = None) -> Path | None:
    """Download and extract musl-dev for a specific architecture."""
    if arch not in ARCH_MAP:
        print(f"Unknown architecture: {arch}", file=sys.stderr)
        print(f"Available: {', '.join(ARCH_MAP.keys())}", file=sys.stderr)
        return None
    
    download_dir = download_dir or DOWNLOAD_DIR
    
    # Get version if not specified
    if not version:
        result = get_musl_version(arch)
        if not result:
            return None
        version, filename = result
    else:
        filename = f"musl-dev-{version}.apk"
    
    print(f"musl-dev {arch} (v{version}):")
    
    # Download directory structure: cache/musl/1.2.5-r21/x86_64/
    version_dir = download_dir / version / arch
    version_dir.mkdir(parents=True, exist_ok=True)
    
    apk_path = version_dir / filename
    extracted_dir = version_dir / "libs"
    
    # Check if already downloaded and extracted
    if extracted_dir.exists() and list(extracted_dir.glob("*.a")):
        lib_count = len(list(extracted_dir.glob("*.a")))
        print(f"  Already downloaded and extracted ({lib_count} libs)")
        return extracted_dir
    
    # Download
    if not apk_path.exists():
        if not download_apk(arch, filename, apk_path):
            return None
    else:
        print(f"  Package already downloaded")
    
    # Extract
    extract_libs(apk_path, extracted_dir)
    
    return extracted_dir


def list_available():
    """List available musl versions and architectures."""
    print("Available musl-dev packages from Alpine Linux:")
    print(f"Mirror: {ALPINE_MIRROR}/{ALPINE_BRANCH}/main/")
    print()
    
    print("Architectures:")
    for alpine_arch, our_arch in ARCH_MAP.items():
        result = get_musl_version(alpine_arch)
        if result:
            version, _ = result
            print(f"  {alpine_arch:12} -> {our_arch:12} (v{version})")
    
    print()
    print("Static libraries included:")
    for lib in WANTED_LIBS:
        print(f"  - {lib}")


def main():
    parser = argparse.ArgumentParser(
        description="Download musl libc static libraries from Alpine Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
    R2_DATA_DIR     Base directory for radare2 data (default: ~/.local/share/radare2)
                    musl libs are stored in $R2_DATA_DIR/cache/musl/

Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --arch x86_64
    %(prog)s --arch x86_64 --version 1.2.5-r21
""",
    )
    
    parser.add_argument("--list", action="store_true", help="List available architectures and versions")
    parser.add_argument("--all", action="store_true", help="Download latest musl-dev for all architectures")
    parser.add_argument("--arch", type=str, help=f"Architecture ({', '.join(ARCH_MAP.keys())})")
    parser.add_argument("--version", type=str, help="musl version (e.g., 1.2.5-r21)")
    parser.add_argument("--output-dir", type=str, help="Output directory (overrides default)")
    
    args = parser.parse_args()
    
    download_dir = DOWNLOAD_DIR
    if args.output_dir:
        download_dir = Path(args.output_dir)
    
    if args.list:
        list_available()
        return
    
    if not args.all and not args.arch:
        parser.print_help()
        return
    
    print(f"Output directory: {download_dir}")
    print()
    
    if args.all:
        # Download for all architectures
        for arch in ARCH_MAP:
            result = download_musl(arch, args.version, download_dir)
            if result:
                print(f"  Output: {result}")
            print()
    elif args.arch:
        result = download_musl(args.arch, args.version, download_dir)
        if result:
            print(f"  Output: {result}")


if __name__ == "__main__":
    main()
