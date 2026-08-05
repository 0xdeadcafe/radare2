#!/usr/bin/env python3
"""
Download Windows VC++ redistributable packages for zsig generation.

This script downloads Visual C++ redistributable packages from Microsoft
and extracts the DLLs for analysis with radare2.

Requirements:
    - cabextract (for extracting .exe installers)
    - Python 3.8+

Usage:
    download-vcredist.py --list           # Show available packages
    download-vcredist.py --all            # Download all packages
    download-vcredist.py --version 2022   # Download specific version
    download-vcredist.py --arch x64       # Download specific arch
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# Default to ~/.local/share/radare2 for XDG compliance
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
DOWNLOAD_DIR = R2_DATA_DIR / "cache" / "vcredist"

# Microsoft Visual C++ Redistributable download URLs
# These are the official aka.ms redirect URLs that always point to latest
VCREDIST_URLS = {
    # VS 2015-2022 (all share same runtime, version 14.x)
    "2022": {
        "x64": "https://aka.ms/vs/17/release/vc_redist.x64.exe",
        "x86": "https://aka.ms/vs/17/release/vc_redist.x86.exe",
        "arm64": "https://aka.ms/vs/17/release/vc_redist.arm64.exe",
    },
    # Older versions with direct download links
    "2019": {
        "x64": "https://aka.ms/vs/16/release/vc_redist.x64.exe",
        "x86": "https://aka.ms/vs/16/release/vc_redist.x86.exe",
        "arm64": "https://aka.ms/vs/16/release/vc_redist.arm64.exe",
    },
    "2017": {
        "x64": "https://aka.ms/vs/15/release/vc_redist.x64.exe",
        "x86": "https://aka.ms/vs/15/release/vc_redist.x86.exe",
    },
    "2015": {
        "x64": "https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x64.exe",
        "x86": "https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x86.exe",
    },
    "2013": {
        "x64": "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe",
        "x86": "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe",
    },
    "2012": {
        "x64": "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe",
        "x86": "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe",
    },
    "2010": {
        "x64": "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe",
        "x86": "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe",
    },
    "2008": {
        "x64": "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe",
        "x86": "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe",
    },
}

# Windows SDK components (from NuGet or direct download)
WINSDK_URLS = {
    # Windows SDK libs are typically obtained from the SDK installer
    # These would need to be extracted from the SDK ISO/installer
}


def check_tools():
    """Check if required extraction tools are available."""
    tools = {
        "cabextract": False,
        "7z": False,
        "msiextract": False,
    }
    
    for tool in tools:
        tools[tool] = shutil.which(tool) is not None
    
    return tools


def download_file(url: str, dest_path: Path, desc: str = None) -> bool:
    """Download a file from URL with progress."""
    desc = desc or url.split("/")[-1]
    print(f"  Downloading {desc}...", end=" ", flush=True)
    
    try:
        # Follow redirects and get final URL
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
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
                        print(f"\r  Downloading {desc}... {pct}%", end="", flush=True)
            
            print(f"\r  Downloading {desc}... OK ({downloaded:,} bytes)")
            return True
            
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def extract_vcredist(exe_path: Path, output_dir: Path, target_arch: str, tools: dict) -> list[Path]:
    """Extract DLLs from a VC++ redistributable installer.
    
    Args:
        exe_path: Path to the vcredist installer exe
        output_dir: Directory to extract files into
        target_arch: Target architecture ('x64', 'x86', or 'arm64')
        tools: Dict of available extraction tools
    
    The vcredist installers are self-extracting CAB files with nested CABs inside.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_files = []
    
    print(f"  Extracting {exe_path.name}...", end=" ", flush=True)
    
    try:
        if tools.get("cabextract"):
            # cabextract can handle self-extracting CABs
            result = subprocess.run(
                ["cabextract", "-d", str(output_dir), str(exe_path)],
                capture_output=True
            )
            if result.returncode == 0:
                # The DLLs are inside nested CAB files (files like a11, a12, etc.)
                # These are actually CAB archives without .cab extension
                for nested_file in output_dir.iterdir():
                    if nested_file.is_file():
                        # Check if it's a CAB archive by file magic
                        try:
                            with open(nested_file, 'rb') as f:
                                magic = f.read(4)
                                if magic == b'MSCF':  # Microsoft Cabinet
                                    subprocess.run(
                                        ["cabextract", "-d", str(output_dir), str(nested_file)],
                                        capture_output=True
                                    )
                        except Exception:
                            pass
        elif tools.get("7z"):
            # 7z can also extract these
            result = subprocess.run(
                ["7z", "x", "-y", f"-o{output_dir}", str(exe_path)],
                capture_output=True
            )
            if result.returncode == 0:
                # Look for nested archives
                for nested in output_dir.iterdir():
                    if nested.is_file():
                        subprocess.run(
                            ["7z", "x", "-y", f"-o{output_dir}", str(nested)],
                            capture_output=True,
                            cwd=output_dir
                        )
        else:
            print("SKIP (no extraction tool)")
            return []
        
        # Find extracted DLLs for the target architecture
        # Files may have _arch suffix like vcruntime140.dll_amd64
        arch_suffix_map = {
            'x64': ['_amd64', '_x64'],
            'x86': ['_x86', '_i386'],
            'arm64': ['_arm64', '_aarch64'],
        }
        
        target_suffixes = arch_suffix_map.get(target_arch, [])
        
        for f in output_dir.rglob("*"):
            if f.is_file():
                name_lower = f.name.lower()
                if '.dll' in name_lower:
                    # Check if this file matches our target architecture
                    has_arch_suffix = any(s in name_lower for suffixes in arch_suffix_map.values() for s in suffixes)
                    
                    if has_arch_suffix:
                        # Only include if it matches target arch
                        if any(s in name_lower for s in target_suffixes):
                            # Rename to remove suffix
                            new_name = f.name
                            for suffix in target_suffixes:
                                new_name = new_name.replace(suffix, '').replace(suffix.upper(), '')
                            if not new_name.lower().endswith('.dll'):
                                # Handle cases like vcruntime140.dll_amd64
                                new_name = new_name.replace('.dll', '') + '.dll'
                            new_path = f.parent / new_name
                            if f != new_path:
                                if new_path.exists():
                                    f.unlink()  # Remove duplicate
                                else:
                                    f.rename(new_path)
                                    extracted_files.append(new_path)
                            else:
                                extracted_files.append(f)
                    else:
                        # No arch suffix - could be the wrong arch, check with file command
                        # For now, skip files without arch suffix as they may be wrong arch
                        pass
        
        # Clean up files from other architectures
        for f in output_dir.rglob("*"):
            if f.is_file():
                name_lower = f.name.lower()
                # Remove files with wrong arch suffix
                for arch_name, suffixes in arch_suffix_map.items():
                    if arch_name != target_arch:
                        for suffix in suffixes:
                            if suffix in name_lower:
                                f.unlink()
                                break
        
        # Also look for .lib files (unlikely in redistributables but worth checking)
        for lib in output_dir.rglob("*.lib"):
            extracted_files.append(lib)
        
        if extracted_files:
            print(f"OK ({len(extracted_files)} files)")
        else:
            print("OK (no DLLs found)")
            
    except Exception as e:
        print(f"FAILED: {e}")
    
    return extracted_files


def download_vcredist(version: str, arch: str, tools: dict, download_only: bool = False) -> Path | None:
    """Download and extract a specific VC++ redistributable."""
    if version not in VCREDIST_URLS:
        print(f"Unknown version: {version}")
        return None
    
    if arch not in VCREDIST_URLS[version]:
        print(f"Architecture {arch} not available for VS{version}")
        return None
    
    url = VCREDIST_URLS[version][arch]
    
    # Download directory structure: cache/vcredist/2022/x64/
    version_dir = DOWNLOAD_DIR / version / arch
    version_dir.mkdir(parents=True, exist_ok=True)
    
    exe_name = f"vc_redist.{arch}.exe" if version >= "2015" else f"vcredist_{arch}.exe"
    exe_path = version_dir / exe_name
    
    # Check if already downloaded
    if exe_path.exists():
        print(f"VS{version} {arch}: Already downloaded")
    else:
        print(f"VS{version} {arch}:")
        if not download_file(url, exe_path, exe_name):
            return None
    
    if download_only:
        return exe_path
    
    # Extract
    extract_dir = version_dir / "extracted"
    if extract_dir.exists() and list(extract_dir.glob("*.dll")):
        print(f"  Already extracted")
    else:
        extract_vcredist(exe_path, extract_dir, arch, tools)
    
    return extract_dir


def list_available():
    """List all available packages."""
    print("Available Visual C++ Redistributables:")
    print()
    for version in sorted(VCREDIST_URLS.keys(), reverse=True):
        archs = ", ".join(sorted(VCREDIST_URLS[version].keys()))
        print(f"  VS{version}: {archs}")
    print()
    print("Note: VS2015-2022 all use the same runtime (14.x), so 2022 covers all.")


def main():
    parser = argparse.ArgumentParser(
        description="Download Windows VC++ redistributable packages for zsig generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
    R2_DATA_DIR     Base directory for radare2 data (default: ~/.local/share/radare2)
                    Downloads stored in $R2_DATA_DIR/cache/vcredist/

Examples:
    %(prog)s --list
    %(prog)s --all
    %(prog)s --version 2022 --arch x64
    %(prog)s --all --download-only
""",
    )
    
    parser.add_argument("--list", action="store_true", help="List available packages")
    parser.add_argument("--all", action="store_true", help="Download all packages")
    parser.add_argument("--version", type=str, help="VS version (2022, 2019, etc)")
    parser.add_argument("--arch", type=str, help="Architecture (x64, x86, arm64)")
    parser.add_argument("--output-dir", type=str, help="Output directory")
    parser.add_argument("--download-only", action="store_true", help="Download without extracting")
    
    args = parser.parse_args()
    
    download_dir = DOWNLOAD_DIR
    if args.output_dir:
        download_dir = Path(args.output_dir)
    
    if args.list:
        list_available()
        return
    
    # Check tools
    tools = check_tools()
    available_tools = [k for k, v in tools.items() if v]
    
    if not available_tools and not args.download_only:
        print("Warning: No extraction tools found.", file=sys.stderr)
        print("Will download only. Install tools to extract:", file=sys.stderr)
        print("  Ubuntu/Debian: apt install cabextract p7zip-full", file=sys.stderr)
        print("  Fedora: dnf install cabextract p7zip", file=sys.stderr)
        print()
        args.download_only = True
    
    if available_tools:
        print(f"Extraction tools: {available_tools}")
    else:
        print("Mode: download only (no extraction tools)")
    print(f"Output directory: {download_dir}")
    print()
    
    if args.all:
        # Download everything
        for version in VCREDIST_URLS:
            for arch in VCREDIST_URLS[version]:
                download_vcredist(version, arch, tools, args.download_only)
                print()
    elif args.version:
        archs = [args.arch] if args.arch else list(VCREDIST_URLS.get(args.version, {}).keys())
        for arch in archs:
            download_vcredist(args.version, arch, tools, args.download_only)
    elif args.arch:
        # Download all versions for this arch
        for version in VCREDIST_URLS:
            if args.arch in VCREDIST_URLS[version]:
                download_vcredist(version, args.arch, tools, args.download_only)
                print()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
