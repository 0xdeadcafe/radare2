#!/usr/bin/env python3
"""
Generate r2 zignatures from Windows SDK static libraries.

This script processes Windows SDK .lib files (COFF archives containing
actual object code, not import libraries) and generates zsig files.

The key insight is that Windows SDK contains two types of .lib files:
1. Import libraries (kernel32.lib, user32.lib) - just stubs, no real code
2. Static libraries (libucrt.lib, bufferoverflow.lib) - actual compiled code

This script processes the static libraries to generate signatures that
can match statically-linked code in binaries.

Usage:
    generate-winsdk-zsig.py --arch x64                    # Generate for one arch
    generate-winsdk-zsig.py --arch x64 --version 10.0.22621.1
    generate-winsdk-zsig.py --all                         # All architectures
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

from zsig_utils import (
    count_signatures,
    merge_zsigs,
    open_r2,
    require_tools,
    get_zsig_output_dir,
    get_cache_dir,
)

# Cache and output directories
WINSDK_CACHE_DIR = get_cache_dir("winsdk")
ZSIG_OUTPUT_DIR = get_zsig_output_dir("windows")


@lru_cache(maxsize=1)
def find_llvm_ar() -> str | None:
    """Find llvm-ar, including versioned names like llvm-ar-19."""
    # Try unversioned first
    if shutil.which("llvm-ar"):
        return "llvm-ar"
    # Try versioned (newest first)
    for path in sorted(glob.glob("/usr/bin/llvm-ar-*"), reverse=True):
        name = os.path.basename(path)
        if shutil.which(name):
            return name
    return None

# Static libraries that contain actual code (not just import stubs)
# These are worth processing for signatures
STATIC_LIBS = [
    # UCRT (Universal C Runtime) - lots of useful signatures
    "libucrt.lib",
    "ucrt.lib",
    # Buffer overflow protection
    "bufferoverflow.lib",
    "bufferoverflowu.lib",
    # Aux utilities
    "aux_ulib.lib",
    # Audio processing (has real code)
    "audiobaseprocessingobject.lib",
    "audiomediatypecrt.lib",
    # NT compatibility
    "ntstc_msvcrt.lib",
]

# Libraries that are definitely import libs (skip these)
IMPORT_LIBS = {
    "kernel32.lib", "ntdll.lib", "user32.lib", "gdi32.lib",
    "advapi32.lib", "shell32.lib", "ole32.lib", "oleaut32.lib",
    "ws2_32.lib", "winhttp.lib", "wininet.lib", "crypt32.lib",
}


def is_import_lib(lib_path: Path) -> bool:
    """Check if a .lib file is an import library (stubs only) vs static library.
    
    Import libraries contain small PE stubs for dynamic linking.
    Static libraries contain actual COFF object files with code.
    """
    # Known import libs - skip these
    if lib_path.name.lower() in {n.lower() for n in IMPORT_LIBS}:
        return True
    
    # Known static libs - don't skip
    if lib_path.name.lower() in {n.lower() for n in STATIC_LIBS}:
        return False
    
    # Heuristic: check archive member sizes
    # Import libs have many tiny members (< 500 bytes each)
    # Static libs have larger .obj files (typically > 1KB)
    try:
        with open(lib_path, 'rb') as f:
            magic = f.read(8)
            if magic != b'!<arch>\n':
                return True  # Not an ar archive
            
            # Sample first few members and check their sizes
            small_members = 0
            large_members = 0
            
            for _ in range(50):  # Check first 50 members
                header = f.read(60)
                if len(header) < 60:
                    break
                
                # Parse size
                try:
                    size_str = header[48:58].decode('ascii').strip()
                    size = int(size_str)
                except ValueError:
                    break
                
                # Skip special members
                name = header[:16].decode('ascii', errors='replace').rstrip()
                if not name.startswith('/') and not name.startswith('#'):
                    if size < 500:
                        small_members += 1
                    else:
                        large_members += 1
                
                # Skip content
                f.seek(size + (size % 2), 1)  # Include padding
            
            # If mostly small members, likely import lib
            if small_members > 0 and large_members == 0:
                return True
            if small_members > large_members * 3:
                return True
                
    except Exception:
        pass
    
    return False


def extract_coff_objects(lib_path: Path, output_dir: Path) -> list[Path]:
    """Extract COFF object files from a Windows .lib archive using llvm-ar.
    
    Windows .lib files are ar archives with COFF object files inside.
    llvm-ar handles Windows paths in member names properly.
    """
    llvm_ar = find_llvm_ar()
    if not llvm_ar:
        print(f"  Warning: llvm-ar not found", file=sys.stderr)
        return []
    
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted = []
    
    # Ensure absolute path for llvm-ar (relative paths fail when cwd changes)
    lib_path = lib_path.resolve()
    
    try:
        # Use llvm-ar to extract - it handles Windows paths
        result = subprocess.run(
            [llvm_ar, "x", str(lib_path)],
            cwd=str(output_dir),
            capture_output=True,
            timeout=60
        )
        
        if result.returncode != 0:
            return []
        
        # Find all extracted .obj files
        # llvm-ar creates files with Windows paths as names (including backslashes)
        # e.g., "d:\os\obj\amd64fre\...\foo.obj"
        obj_index = 0
        for item in output_dir.iterdir():
            if item.is_file():
                name_lower = item.name.lower()
                # Check if filename ends with .obj (accounting for Windows backslash paths)
                if name_lower.endswith('.obj'):
                    # Rename to simple name
                    new_name = f"obj_{obj_index:04d}.obj"
                    new_path = output_dir / new_name
                    item.rename(new_path)
                    extracted.append(new_path)
                    obj_index += 1
        
        # Clean up any directories created by extraction
        for item in list(output_dir.iterdir()):
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
        
    except Exception as e:
        print(f"  Warning: Error extracting {lib_path.name}: {e}", file=sys.stderr)
    
    return extracted


def process_static_lib(lib_path: Path, output_zsig: Path, prefix: str = None) -> tuple[bool, list[Path]]:
    """Process a static library and generate zsig file.
    
    Args:
        lib_path: Path to the .lib file
        output_zsig: Path for output .zsig file
        prefix: Prefix for signature names
        
    Returns:
        Tuple of (success, obj_files) where obj_files contains extracted object paths
    """
    lib_name = lib_path.stem
    prefix = prefix or lib_name
    
    print(f"  Processing {lib_path.name}...", end=" ", flush=True)
    
    # Check if it's worth processing
    if is_import_lib(lib_path):
        print("SKIP (import lib)")
        return False, []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        work_dir = Path(temp_dir)
        
        # Create lib-specific subdirectory
        lib_work_dir = work_dir / lib_name
        lib_work_dir.mkdir(parents=True, exist_ok=True)
        
        # Extract COFF objects
        obj_files = extract_coff_objects(lib_path, lib_work_dir)
        
        if not obj_files:
            print("SKIP (no objects)")
            return False, []
        
        print(f"{len(obj_files)} objects...", end=" ", flush=True)
        
        # Generate zsigs from each object
        total_sigs = 0
        zsig_parts = []
        
        for obj_path in obj_files:
            try:
                with open_r2(str(obj_path)) as r2:
                    r2.cmd(f"e zign.prefix={prefix}")
                    r2.cmd("aa")
                    r2.cmd("zg")
                    
                    # Save to temp file
                    part_zsig = lib_work_dir / f"{obj_path.stem}.zsig"
                    
                    obj_sigs = count_signatures(r2)
                    
                    if obj_sigs > 0:
                        r2.cmd(f"zos {part_zsig}")
                        if part_zsig.exists() and part_zsig.stat().st_size > 0:
                            zsig_parts.append(str(part_zsig))
                            total_sigs += obj_sigs
            except Exception:
                pass
        
        if not zsig_parts:
            print("SKIP (no signatures)")
            return False, []
        
        # Merge all parts
        output_zsig.parent.mkdir(parents=True, exist_ok=True)
        
        success, final_count = merge_zsigs(zsig_parts, str(output_zsig))
        
        if success and output_zsig.exists():
            size = output_zsig.stat().st_size
            sig_count = final_count if final_count > 0 else total_sigs
            print(f"OK ({sig_count} sigs, {size:,} bytes)")
            return True, obj_files
        else:
            print("FAILED")
            return False, []


def find_sdk_dir(arch: str, version: str = None, cache_dir: Path = None) -> Path | None:
    """Find the Windows SDK libs directory for given arch and version."""
    cache_dir = cache_dir or WINSDK_CACHE_DIR
    
    if version:
        sdk_dir = cache_dir / version / arch / "libs"
        if sdk_dir.exists():
            return sdk_dir
        return None
    
    # Find latest version
    if not cache_dir.exists():
        return None
    
    versions = sorted([d.name for d in cache_dir.iterdir() if d.is_dir()])
    if not versions:
        return None
    
    for ver in reversed(versions):
        sdk_dir = cache_dir / ver / arch / "libs"
        if sdk_dir.exists():
            return sdk_dir
    
    return None


def process_arch(arch: str, version: str = None, cache_dir: Path = None, 
                 output_dir: Path = None) -> bool:
    """Process all static libraries for an architecture.
    
    Args:
        arch: Target architecture (x64, x86, arm64)
        version: SDK version (optional, uses latest if not specified)
        cache_dir: Override SDK cache directory
        output_dir: Override zsig output directory
    """
    cache_dir = cache_dir or WINSDK_CACHE_DIR
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    
    sdk_dir = find_sdk_dir(arch, version, cache_dir)
    
    if not sdk_dir:
        print(f"Error: No SDK found for {arch}", file=sys.stderr)
        print(f"Run: download-windows-sdk.py --arch {arch}", file=sys.stderr)
        return False
    
    # Determine version from path
    actual_version = sdk_dir.parent.parent.name
    
    print(f"\n=== Windows SDK {arch} (v{actual_version}) ===")
    print(f"Source: {sdk_dir}")
    
    arch_output_dir = output_dir / arch
    arch_output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Process each static library
        libs_processed = 0
        
        # First, try the known static libraries
        for lib_name in STATIC_LIBS:
            lib_path = sdk_dir / lib_name
            if lib_path.exists():
                output_zsig = arch_output_dir / f"winsdk-{lib_path.stem}.zsig"
                if output_zsig.exists():
                    print(f"  {lib_name}: already exists, skipping")
                    libs_processed += 1
                else:
                    success, _ = process_static_lib(lib_path, output_zsig, 
                                                    prefix=lib_path.stem)
                    if success:
                        libs_processed += 1
        
        # Also look for any other large libs that might be static
        for lib_path in sorted(sdk_dir.glob("*.lib")):
            if lib_path.name.lower() in [l.lower() for l in STATIC_LIBS]:
                continue  # Already processed
            if lib_path.name.lower() in IMPORT_LIBS:
                continue  # Skip known import libs
            
            # Skip debug libraries (they're duplicates with debug info)
            if lib_path.stem.endswith('d') and (sdk_dir / f"{lib_path.stem[:-1]}.lib").exists():
                continue
            
            # Only process libs in a reasonable size range (500KB - 5MB)
            # Very large libs (>5MB) are mostly duplicates or debug versions
            size = lib_path.stat().st_size
            if 500_000 < size < 5_000_000:
                output_zsig = arch_output_dir / f"winsdk-{lib_path.stem}.zsig"
                if not output_zsig.exists():
                    success, obj_files = process_static_lib(lib_path, output_zsig, 
                                                            prefix=lib_path.stem)
                    if success:
                        libs_processed += 1
        
        if libs_processed > 0:
            print(f"\nGenerated {libs_processed} zsig files in {arch_output_dir}")
            return True
        else:
            print("\nNo zsig files generated")
            return False
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False


def main():
    # Check for required tools upfront
    llvm_ar = find_llvm_ar()
    if not llvm_ar:
        print("Error: llvm-ar not found", file=sys.stderr)
        print("Install with: apt install llvm", file=sys.stderr)
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Generate r2 zignatures from Windows SDK static libraries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
    R2_DATA_DIR     Base directory for radare2 data (default: ~/.local/share/radare2)
                    SDK libs read from $R2_DATA_DIR/cache/winsdk/
                    Zsigs written to $R2_DATA_DIR/zigns/windows/

Examples:
    %(prog)s --arch x64
    %(prog)s --all
    %(prog)s --lib libucrt.lib -o ucrt.zsig
""",
    )
    
    parser.add_argument('--arch', type=str, help="Architecture (x64, x86, arm64)")
    parser.add_argument('--version', type=str, help="SDK version (e.g., 10.0.22621.1)")
    parser.add_argument('--all', action='store_true', help="Process all architectures")
    parser.add_argument('--lib', type=str, help="Process a specific .lib file")
    parser.add_argument('-o', '--output', type=str, help="Output zsig path")
    parser.add_argument('--cache-dir', type=str, help="Override SDK cache directory")
    parser.add_argument('--output-dir', type=str, help="Override zsig output directory")
    
    args = parser.parse_args()
    
    cache_dir = Path(args.cache_dir) if args.cache_dir else WINSDK_CACHE_DIR
    output_dir = Path(args.output_dir) if args.output_dir else ZSIG_OUTPUT_DIR
    
    if args.lib:
        # Single lib mode
        lib_path = Path(args.lib)
        if not lib_path.exists():
            print(f"Error: {lib_path} not found", file=sys.stderr)
            sys.exit(1)
        
        output = Path(args.output) if args.output else Path(f"{lib_path.stem}.zsig")
        success, obj_files = process_static_lib(lib_path, output)
        sys.exit(0 if success else 1)
    
    elif args.all:
        success = False
        for arch in ['x64', 'x86', 'arm64']:
            if process_arch(arch, args.version, cache_dir, output_dir):
                success = True
        sys.exit(0 if success else 1)
    
    elif args.arch:
        if process_arch(args.arch, args.version, cache_dir, output_dir):
            sys.exit(0)
        else:
            sys.exit(1)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
