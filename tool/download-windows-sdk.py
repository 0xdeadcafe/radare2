#!/usr/bin/env python3
"""
Download Windows SDK import libraries from NuGet for zsig generation.

This script downloads Microsoft.Windows.SDK.CPP.* NuGet packages and extracts
the .lib import libraries for kernel32, ntdll, user32, etc.

Requirements:
    - unzip (for extracting .nupkg files - they're just ZIP files)
    - Python 3.8+

Usage:
    download-windows-sdk.py --list           # Show available SDK versions
    download-windows-sdk.py --all            # Download latest SDK for all archs
    download-windows-sdk.py --arch x64       # Download specific arch
    download-windows-sdk.py --version 10.0.22621.1  # Download specific version
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

# Default to ~/.local/share/radare2 for XDG compliance
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
DOWNLOAD_DIR = R2_DATA_DIR / "cache" / "winsdk"

# NuGet API endpoints
NUGET_INDEX = "https://api.nuget.org/v3-flatcontainer"

# Package names for each architecture
SDK_PACKAGES = {
    "x64": "microsoft.windows.sdk.cpp.x64",
    "x86": "microsoft.windows.sdk.cpp.x86",
    "arm64": "microsoft.windows.sdk.cpp.arm64",
}

# Common Windows SDK libraries we want to extract
WANTED_LIBS = [
    # Core Windows APIs
    "kernel32.lib",
    "kernelbase.lib",
    "ntdll.lib",
    "user32.lib",
    "gdi32.lib",
    "advapi32.lib",
    "shell32.lib",
    "ole32.lib",
    "oleaut32.lib",
    "comdlg32.lib",
    "comctl32.lib",
    # Networking
    "ws2_32.lib",
    "winhttp.lib",
    "wininet.lib",
    "iphlpapi.lib",
    # Security/Crypto
    "crypt32.lib",
    "bcrypt.lib",
    "ncrypt.lib",
    "secur32.lib",
    # Other common libs
    "shlwapi.lib",
    "version.lib",
    "winspool.lib",
    "setupapi.lib",
    "rpcrt4.lib",
    "uuid.lib",
    "dbghelp.lib",
    "psapi.lib",
    # Runtime
    "ntdllp.lib",
    "mincore.lib",
    "onecoreuap.lib",
]


def get_available_versions(package_name: str) -> list[str]:
    """Get list of available versions for a NuGet package."""
    url = f"{NUGET_INDEX}/{package_name}/index.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read())
            return data.get("versions", [])
    except Exception as e:
        print(f"Error fetching versions for {package_name}: {e}", file=sys.stderr)
        return []


def get_latest_stable_version(versions: list[str]) -> str | None:
    """Get the latest non-preview version."""
    stable = [v for v in versions if "preview" not in v.lower() and "rtm" not in v.lower()]
    return stable[-1] if stable else None


def download_nupkg(package_name: str, version: str, dest_path: Path) -> bool:
    """Download a NuGet package."""
    url = f"{NUGET_INDEX}/{package_name}/{version}/{package_name}.{version}.nupkg"
    print(f"  Downloading {package_name} v{version}...", end=" ", flush=True)
    
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
                        print(f"\r  Downloading {package_name} v{version}... {pct}%", end="", flush=True)
            
            print(f"\r  Downloading {package_name} v{version}... OK ({downloaded:,} bytes)")
            return True
            
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def extract_libs(nupkg_path: Path, output_dir: Path) -> list[Path]:
    """Extract .lib files from a NuGet package.
    
    The SDK packages have structure:
    c/um/{arch}/kernel32.lib
    c/ucrt/{arch}/libucrt.lib
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_libs = []
    
    print(f"  Extracting libs...", end=" ", flush=True)
    
    try:
        with zipfile.ZipFile(nupkg_path, 'r') as zf:
            # List all .lib files (case-insensitive - NuGet has .Lib and .lib)
            lib_files = [f for f in zf.namelist() if f.lower().endswith('.lib')]
            
            for lib_path in lib_files:
                lib_name = os.path.basename(lib_path).lower()
                
                # Extract all libs, or just wanted ones
                # Let's extract all and let the zsig generator decide
                dest_file = output_dir / lib_name
                
                # Handle duplicates by keeping the one from um/ directory (preferred)
                if dest_file.exists():
                    # Prefer um/ over ucrt/
                    if '/um/' not in lib_path:
                        continue
                
                with zf.open(lib_path) as src, open(dest_file, 'wb') as dst:
                    dst.write(src.read())
                extracted_libs.append(dest_file)
        
        # Remove duplicates from list (keep unique paths)
        extracted_libs = list(set(extracted_libs))
        print(f"OK ({len(extracted_libs)} .lib files)")
        
        # List some key libs found
        key_libs = [l for l in extracted_libs if l.name.lower() in [w.lower() for w in WANTED_LIBS[:10]]]
        if key_libs:
            print(f"    Key libs: {', '.join(l.name for l in sorted(key_libs)[:5])}...")
        
    except Exception as e:
        print(f"FAILED: {e}")
    
    return extracted_libs


def download_sdk(arch: str, version: str = None, download_dir: Path = None) -> Path | None:
    """Download and extract Windows SDK for a specific architecture."""
    if arch not in SDK_PACKAGES:
        print(f"Unknown architecture: {arch}", file=sys.stderr)
        print(f"Available: {', '.join(SDK_PACKAGES.keys())}", file=sys.stderr)
        return None
    
    download_dir = download_dir or DOWNLOAD_DIR
    package_name = SDK_PACKAGES[arch]
    
    # Get version if not specified
    if not version:
        versions = get_available_versions(package_name)
        if not versions:
            print(f"Could not fetch versions for {package_name}", file=sys.stderr)
            return None
        version = get_latest_stable_version(versions)
        if not version:
            print(f"No stable version found for {package_name}", file=sys.stderr)
            return None
    
    print(f"Windows SDK {arch} (v{version}):")
    
    # Download directory structure: cache/winsdk/10.0.22621.1/x64/
    version_dir = download_dir / version / arch
    version_dir.mkdir(parents=True, exist_ok=True)
    
    nupkg_path = version_dir / f"{package_name}.{version}.nupkg"
    extracted_dir = version_dir / "libs"
    
    # Check if already downloaded and extracted
    if extracted_dir.exists() and list(extracted_dir.glob("*.lib")):
        lib_count = len(list(extracted_dir.glob("*.lib")))
        print(f"  Already downloaded and extracted ({lib_count} libs)")
        return extracted_dir
    
    # Download
    if not nupkg_path.exists():
        if not download_nupkg(package_name, version, nupkg_path):
            return None
    else:
        print(f"  Package already downloaded")
    
    # Extract
    extract_libs(nupkg_path, extracted_dir)
    
    return extracted_dir


def list_available():
    """List available SDK versions."""
    print("Available Windows SDK versions (from NuGet):")
    print()
    
    # Check x64 package for versions (all archs have same versions)
    versions = get_available_versions(SDK_PACKAGES["x64"])
    if not versions:
        print("  Error: Could not fetch version list", file=sys.stderr)
        return
    
    # Filter to stable versions
    stable = [v for v in versions if "preview" not in v.lower() and "rtm" not in v.lower()]
    
    print("Stable versions (latest 10):")
    for v in stable[-10:]:
        print(f"  {v}")
    
    print()
    print(f"Latest stable: {stable[-1]}")
    print()
    print("Architectures available: x64, x86, arm64")
    print()
    print("Key libraries included:")
    for lib in WANTED_LIBS[:15]:
        print(f"  - {lib}")
    print("  ... and many more")


def main():
    parser = argparse.ArgumentParser(
        description="Download Windows SDK import libraries from NuGet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
    R2_DATA_DIR     Base directory for radare2 data (default: ~/.local/share/radare2)
                    SDK libs are stored in $R2_DATA_DIR/cache/winsdk/

Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --arch x64
    %(prog)s --arch x64 --version 10.0.22621.1
""",
    )
    
    parser.add_argument("--list", action="store_true", help="List available SDK versions")
    parser.add_argument("--all", action="store_true", help="Download latest SDK for all architectures")
    parser.add_argument("--arch", type=str, help="Architecture (x64, x86, arm64)")
    parser.add_argument("--version", type=str, help="SDK version (e.g., 10.0.22621.1)")
    parser.add_argument("--output-dir", type=str, help="Output directory (overrides default)")
    
    args = parser.parse_args()
    
    download_dir = DOWNLOAD_DIR
    if args.output_dir:
        download_dir = Path(args.output_dir)
    
    if args.list:
        list_available()
        return
    
    print(f"Output directory: {download_dir}")
    print()
    
    if args.all:
        # Download for all architectures
        for arch in SDK_PACKAGES:
            result = download_sdk(arch, args.version, download_dir)
            if result:
                print(f"  Output: {result}")
            print()
    elif args.arch:
        result = download_sdk(args.arch, args.version, download_dir)
        if result:
            print(f"  Output: {result}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
