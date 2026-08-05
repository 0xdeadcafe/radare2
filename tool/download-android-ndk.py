#!/usr/bin/env python3
"""
Download Android NDK and extract static libraries for zsig generation.

This script downloads the Android NDK from Google and extracts the static
libraries (libc.a, libm.a, etc.) for signature generation.

Requirements:
    - Python 3.8+
    - unzip (for extracting NDK archive)

Usage:
    download-android-ndk.py --list              # Show available NDK versions/architectures
    download-android-ndk.py --all               # Download latest NDK for all archs
    download-android-ndk.py --arch arm64-v8a    # Download specific arch
    download-android-ndk.py --version r27c      # Download specific version
    download-android-ndk.py --use-local         # Use existing ANDROID_NDK_HOME
"""
import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

# Default to ~/.local/share/radare2 for XDG compliance
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
DOWNLOAD_DIR = R2_DATA_DIR / "cache" / "android-ndk"

# NDK download URLs (Google's CDN)
# Format: https://dl.google.com/android/repository/android-ndk-{version}-{platform}.zip
NDK_BASE_URL = "https://dl.google.com/android/repository"

# Available NDK versions (latest LTS versions)
NDK_VERSIONS = {
    "r27c": {
        "linux": "android-ndk-r27c-linux.zip",
        "darwin": "android-ndk-r27c-darwin.zip",
        "windows": "android-ndk-r27c-windows.zip",
    },
    "r26d": {
        "linux": "android-ndk-r26d-linux.zip",
        "darwin": "android-ndk-r26d-darwin.zip",
        "windows": "android-ndk-r26d-windows.zip",
    },
    "r25c": {
        "linux": "android-ndk-r25c-linux.zip",
        "darwin": "android-ndk-r25c-darwin.zip",
        "windows": "android-ndk-r25c-windows.zip",
    },
}

DEFAULT_VERSION = "r27c"

# Architecture mapping (Android ABI -> our output name)
# These match the directory names in NDK sysroot
ARCH_MAP = {
    "arm64-v8a": "aarch64-linux-android",
    "armeabi-v7a": "arm-linux-androideabi",
    "x86_64": "x86_64-linux-android",
    "x86": "i686-linux-android",
}

# Reverse mapping for user convenience
ABI_ALIASES = {
    "arm64": "arm64-v8a",
    "aarch64": "arm64-v8a",
    "arm": "armeabi-v7a",
    "armv7": "armeabi-v7a",
    "x64": "x86_64",
}

# Static libraries we want to extract
WANTED_LIBS = [
    "libc.a",               # Bionic C library
    "libm.a",               # Math library
    "libdl.a",              # Dynamic linking stubs
    "liblog.a",             # Android logging
    "libz.a",               # Compression (zlib)
    "libc++_static.a",      # C++ standard library
    "libc++abi.a",          # C++ ABI support
    "libandroid_support.a", # Android support (older APIs)
]


def get_platform() -> str:
    """Get current platform name."""
    import platform
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "darwin"
    elif system == "windows":
        return "windows"
    else:
        return "linux"  # Default fallback


def download_file(url: str, dest_path: Path, desc: str = None) -> bool:
    """Download a file from URL with progress."""
    import urllib.request
    
    desc = desc or url.split("/")[-1]
    print(f"  Downloading {desc}...", end=" ", flush=True)
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=300) as response:
            total_size = response.getheader("Content-Length")
            total_size = int(total_size) if total_size else None
            
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(dest_path, "wb") as f:
                downloaded = 0
                block_size = 65536  # 64KB blocks for large file
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    f.write(buffer)
                    downloaded += len(buffer)
                    if total_size:
                        pct = downloaded * 100 // total_size
                        mb = downloaded // (1024 * 1024)
                        print(f"\r  Downloading {desc}... {pct}% ({mb}MB)", end="", flush=True)
            
            mb = downloaded // (1024 * 1024)
            print(f"\r  Downloading {desc}... OK ({mb}MB)          ")
            return True
            
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def extract_ndk(zip_path: Path, extract_dir: Path) -> Path | None:
    """Extract NDK zip file.
    
    Returns path to extracted NDK root directory.
    """
    print(f"  Extracting NDK...", end=" ", flush=True)
    
    try:
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Get the root directory name from the archive
            root_dirs = set()
            for name in zf.namelist():
                parts = name.split('/')
                if parts[0]:
                    root_dirs.add(parts[0])
            
            if len(root_dirs) != 1:
                print(f"FAILED: unexpected archive structure")
                return None
            
            ndk_root = extract_dir / list(root_dirs)[0]
            
            # Skip if already extracted
            if ndk_root.exists() and (ndk_root / "toolchains").exists():
                print("already extracted")
                return ndk_root
            
            # Extract all files
            total = len(zf.namelist())
            for i, member in enumerate(zf.namelist()):
                zf.extract(member, extract_dir)
                if i % 1000 == 0:
                    pct = i * 100 // total
                    print(f"\r  Extracting NDK... {pct}%", end="", flush=True)
        
        print(f"\r  Extracting NDK... OK          ")
        return ndk_root
        
    except Exception as e:
        print(f"FAILED: {e}")
        return None


def find_sysroot_libs(ndk_root: Path, abi: str, api_level: int = 21) -> Path | None:
    """Find the sysroot library directory for a given ABI.
    
    NDK structure (modern unified toolchain):
    toolchains/llvm/prebuilt/{host}/sysroot/usr/lib/{triple}/{api}/
    
    Returns path to the library directory or None.
    """
    if abi not in ARCH_MAP:
        return None
    
    triple = ARCH_MAP[abi]
    
    # Find prebuilt directory (varies by host OS)
    prebuilt = ndk_root / "toolchains" / "llvm" / "prebuilt"
    if not prebuilt.exists():
        return None
    
    # Get host directory (e.g., linux-x86_64, darwin-x86_64)
    host_dirs = list(prebuilt.iterdir())
    if not host_dirs:
        return None
    host_dir = host_dirs[0]
    
    # Sysroot library path
    lib_dir = host_dir / "sysroot" / "usr" / "lib" / triple
    if not lib_dir.exists():
        return None
    
    # Find highest available API level up to requested
    available_apis = []
    for d in lib_dir.iterdir():
        if d.is_dir() and d.name.isdigit():
            available_apis.append(int(d.name))
    
    if not available_apis:
        # Some libs are in the triple directory directly
        return lib_dir
    
    # Use highest API <= requested, or lowest available
    available_apis.sort()
    target_api = api_level
    for api in reversed(available_apis):
        if api <= target_api:
            return lib_dir / str(api)
    
    return lib_dir / str(available_apis[0])


def extract_libs(ndk_root: Path, abi: str, output_dir: Path) -> list[Path]:
    """Extract static libraries for a specific ABI.
    
    Returns list of extracted library paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted = []
    
    lib_dir = find_sysroot_libs(ndk_root, abi)
    if not lib_dir:
        print(f"  Could not find sysroot libs for {abi}")
        return []
    
    print(f"  Sysroot: {lib_dir.relative_to(ndk_root)}")
    
    # Also check parent directory (some libs like libc++_static.a are there)
    search_dirs = [lib_dir]
    if lib_dir.name.isdigit():
        search_dirs.append(lib_dir.parent)
    
    # Find and copy wanted libraries
    found_libs = set()
    for search_dir in search_dirs:
        for lib_file in search_dir.glob("*.a"):
            if lib_file.name in WANTED_LIBS or lib_file.name.startswith("lib"):
                if lib_file.name not in found_libs:
                    dest = output_dir / lib_file.name
                    shutil.copy2(lib_file, dest)
                    extracted.append(dest)
                    found_libs.add(lib_file.name)
    
    if extracted:
        print(f"  Extracted {len(extracted)} libraries")
        # Show key libs
        key_libs = [l.name for l in extracted if l.name in WANTED_LIBS]
        if key_libs:
            print(f"    Key libs: {', '.join(sorted(key_libs)[:5])}{'...' if len(key_libs) > 5 else ''}")
    
    return extracted


def download_ndk(version: str, abi: str, download_dir: Path = None, use_local: bool = False) -> Path | None:
    """Download NDK and extract libraries for a specific ABI.
    
    Returns path to extracted libraries directory.
    """
    # Resolve ABI aliases
    if abi in ABI_ALIASES:
        abi = ABI_ALIASES[abi]
    
    if abi not in ARCH_MAP:
        print(f"Unknown ABI: {abi}", file=sys.stderr)
        print(f"Available: {', '.join(ARCH_MAP.keys())}", file=sys.stderr)
        return None
    
    download_dir = download_dir or DOWNLOAD_DIR
    
    # Check for local NDK installation
    ndk_root = None
    if use_local:
        ndk_home = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("NDK_HOME")
        if ndk_home:
            ndk_root = Path(ndk_home)
            if not (ndk_root / "toolchains").exists():
                print(f"  ANDROID_NDK_HOME invalid: {ndk_home}")
                ndk_root = None
            else:
                print(f"Using local NDK: {ndk_root}")
    
    # Download if no local NDK
    if not ndk_root:
        if version not in NDK_VERSIONS:
            print(f"Unknown NDK version: {version}", file=sys.stderr)
            print(f"Available: {', '.join(NDK_VERSIONS.keys())}", file=sys.stderr)
            return None
        
        platform = get_platform()
        if platform not in NDK_VERSIONS[version]:
            print(f"Platform {platform} not available for NDK {version}")
            return None
        
        filename = NDK_VERSIONS[version][platform]
        url = f"{NDK_BASE_URL}/{filename}"
        
        version_dir = download_dir / version
        version_dir.mkdir(parents=True, exist_ok=True)
        
        zip_path = version_dir / filename
        extract_dir = version_dir / "extracted"
        
        print(f"NDK {version} {abi}:")
        
        # Download if needed
        if not zip_path.exists():
            if not download_file(url, zip_path, filename):
                return None
        else:
            size_mb = zip_path.stat().st_size // (1024 * 1024)
            print(f"  Already downloaded ({size_mb}MB)")
        
        # Extract NDK
        ndk_root = extract_ndk(zip_path, extract_dir)
        if not ndk_root:
            return None
    
    # Extract libraries for this ABI
    libs_dir = download_dir / version / "libs" / abi
    if libs_dir.exists() and list(libs_dir.glob("*.a")):
        lib_count = len(list(libs_dir.glob("*.a")))
        print(f"  Libraries already extracted ({lib_count} files)")
        return libs_dir
    
    extract_libs(ndk_root, abi, libs_dir)
    
    return libs_dir


def list_available():
    """List available NDK versions and architectures."""
    print("Android NDK Downloader")
    print()
    print("Available NDK versions:")
    for version in NDK_VERSIONS:
        platforms = ", ".join(NDK_VERSIONS[version].keys())
        default = " (default)" if version == DEFAULT_VERSION else ""
        print(f"  {version}: {platforms}{default}")
    
    print()
    print("Target architectures (ABIs):")
    for abi, triple in ARCH_MAP.items():
        aliases = [k for k, v in ABI_ALIASES.items() if v == abi]
        alias_str = f" (aliases: {', '.join(aliases)})" if aliases else ""
        print(f"  {abi:15} -> {triple}{alias_str}")
    
    print()
    print("Static libraries extracted:")
    for lib in WANTED_LIBS:
        print(f"  - {lib}")
    
    print()
    print("Environment variables:")
    print("  ANDROID_NDK_HOME  Use existing NDK installation (with --use-local)")
    print("  R2_DATA_DIR       Base directory for downloads (default: ~/.local/share/radare2)")


def main():
    parser = argparse.ArgumentParser(
        description="Download Android NDK and extract static libraries for zsig generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
    ANDROID_NDK_HOME    Path to existing NDK installation (use with --use-local)
    R2_DATA_DIR         Base directory for radare2 data (default: ~/.local/share/radare2)
                        NDK cached in $R2_DATA_DIR/cache/android-ndk/

Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --arch arm64-v8a
    %(prog)s --arch arm64 --version r26d
    %(prog)s --use-local --arch arm64-v8a
""",
    )
    
    parser.add_argument("--list", action="store_true", help="List available versions and architectures")
    parser.add_argument("--all", action="store_true", help="Download and extract for all architectures")
    parser.add_argument("--arch", type=str, help=f"Target ABI ({', '.join(ARCH_MAP.keys())})")
    parser.add_argument("--version", type=str, default=DEFAULT_VERSION, help=f"NDK version (default: {DEFAULT_VERSION})")
    parser.add_argument("--use-local", action="store_true", help="Use existing ANDROID_NDK_HOME instead of downloading")
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
        for abi in ARCH_MAP:
            result = download_ndk(args.version, abi, download_dir, args.use_local)
            if result:
                print(f"  Output: {result}")
            print()
    elif args.arch:
        result = download_ndk(args.version, args.arch, download_dir, args.use_local)
        if result:
            print(f"  Output: {result}")


if __name__ == "__main__":
    main()
