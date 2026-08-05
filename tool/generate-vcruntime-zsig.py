#!/usr/bin/env python3
"""
Generate r2 zignatures from Windows PE/DLL files.

This script processes Windows DLLs (from VC++ redistributables) and generates
zsig files for function recognition.

Usage:
    generate-vcruntime-zsig.py --dir /path/to/extracted/dlls -o vs2022-x64.zsig
    generate-vcruntime-zsig.py --dll vcruntime140.dll -o vcruntime.zsig
    generate-vcruntime-zsig.py --version 2022 --arch x64  # Auto-find in cache
"""
import argparse
import sys
from pathlib import Path

from zsig_utils import (
    generate_zsig_from_dll,
    merge_zsigs,
    get_zsig_output_dir,
    get_cache_dir,
)

# Cache and output directories
VCREDIST_CACHE_DIR = get_cache_dir("vcredist")
ZSIG_OUTPUT_DIR = get_zsig_output_dir("windows")

# DLLs worth processing from vcredist packages
# These contain actual runtime code (not just stubs)
VCRUNTIME_DLLS = [
    "vcruntime140.dll",
    "vcruntime140_1.dll",  # Additional vcruntime
    "msvcp140.dll",        # C++ standard library
    "msvcp140_1.dll",      # Additional C++ runtime
    "msvcp140_2.dll",      # Additional C++ runtime
    "concrt140.dll",       # Concurrency runtime
    "vccorlib140.dll",     # C++ CRT for Windows Runtime
    "vcomp140.dll",        # OpenMP runtime
    "vcamp140.dll",        # C++ AMP runtime
]


def find_dlls_in_dir(dll_dir: Path) -> list[Path]:
    """Find DLL files in a directory.
    
    Args:
        dll_dir: Directory to search
        
    Returns:
        List of paths to DLL files
    """
    dlls = []
    for f in dll_dir.iterdir():
        if f.is_file() and f.suffix.lower() == '.dll':
            dlls.append(f)
    return sorted(dlls)


def find_vcredist_dir(version: str, arch: str, cache_dir: Path = None) -> Path | None:
    """Find extracted vcredist directory for given version and arch.
    
    Args:
        version: VS version (e.g., "2022")
        arch: Architecture (e.g., "x64")
        cache_dir: Override cache directory
        
    Returns:
        Path to extracted directory, or None if not found
    """
    cache_dir = cache_dir or VCREDIST_CACHE_DIR
    extracted_dir = cache_dir / version / arch / "extracted"
    
    if extracted_dir.exists() and list(extracted_dir.glob("*.dll")):
        return extracted_dir
    return None


def process_dll(dll_path: Path, output_zsig: Path, prefix: str = None) -> tuple[bool, int]:
    """Process a single DLL and generate zsig.
    
    Args:
        dll_path: Path to the DLL file
        output_zsig: Output path for zsig file
        prefix: Signature prefix (derived from filename if None)
        
    Returns:
        Tuple of (success, signature_count)
    """
    dll_name = dll_path.stem
    prefix = prefix or dll_name.lower().replace("-", "_")
    
    print(f"  Processing {dll_path.name}...", end=" ", flush=True)
    
    # Create output directory
    output_zsig.parent.mkdir(parents=True, exist_ok=True)
    
    success, sig_count = generate_zsig_from_dll(
        str(dll_path),
        str(output_zsig),
        prefix=prefix,
        log=lambda msg: print(f"\n    {msg}", file=sys.stderr)
    )
    
    if success:
        size = output_zsig.stat().st_size
        print(f"OK ({sig_count} sigs, {size:,} bytes)")
        return True, sig_count
    else:
        print("SKIP (no signatures)")
        return False, 0


def process_directory(
    dll_dir: Path,
    output_path: Path,
    prefix: str = None,
    version: str = None,
    arch: str = None
) -> bool:
    """Process all DLLs in a directory and merge into single zsig.
    
    Args:
        dll_dir: Directory containing DLL files
        output_path: Output path for merged zsig
        prefix: Base prefix for signatures
        version: VS version for metadata
        arch: Architecture for metadata
        
    Returns:
        True if successful
    """
    dlls = find_dlls_in_dir(dll_dir)
    
    if not dlls:
        print(f"Error: No DLLs found in {dll_dir}", file=sys.stderr)
        return False
    
    print(f"Found {len(dlls)} DLLs in {dll_dir}")
    
    # Process each DLL
    zsig_parts = []
    total_sigs = 0
    
    for dll_path in dlls:
        dll_name = dll_path.stem
        dll_prefix = f"{prefix}_{dll_name}" if prefix else dll_name
        
        # Generate individual zsig
        part_zsig = dll_dir / f"{dll_name}.zsig"
        
        success, sig_count = process_dll(dll_path, part_zsig, prefix=dll_prefix.lower().replace("-", "_"))
        if success:
            zsig_parts.append(str(part_zsig))
            total_sigs += sig_count
    
    if not zsig_parts:
        print("Error: No signatures generated from any DLLs", file=sys.stderr)
        return False
    
    # Merge all parts
    print(f"\nMerging {len(zsig_parts)} zsig files...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    success, final_count = merge_zsigs(zsig_parts, str(output_path))
    
    if success:
        size = output_path.stat().st_size
        print(f"Created {output_path} ({final_count or total_sigs} sigs, {size:,} bytes)")
        
        # Clean up individual zsig files
        for part in zsig_parts:
            try:
                Path(part).unlink()
                meta_path = Path(part + ".meta")
                if meta_path.exists():
                    meta_path.unlink()
            except Exception:
                pass
        
        return True
    else:
        print("Error: Failed to merge zsig files", file=sys.stderr)
        return False


def process_version(version: str, arch: str, cache_dir: Path = None, 
                    output_dir: Path = None) -> bool:
    """Process vcredist for a specific version and architecture.
    
    Args:
        version: VS version (e.g., "2022")
        arch: Architecture (e.g., "x64")
        cache_dir: Override cache directory
        output_dir: Override output directory
        
    Returns:
        True if successful
    """
    cache_dir = cache_dir or VCREDIST_CACHE_DIR
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    
    dll_dir = find_vcredist_dir(version, arch, cache_dir)
    
    if not dll_dir:
        print(f"Error: VS{version} {arch} not found in cache", file=sys.stderr)
        print(f"Run: download-vcredist.py --version {version} --arch {arch}", file=sys.stderr)
        return False
    
    print(f"\n=== VC++ Runtime VS{version} {arch} ===")
    print(f"Source: {dll_dir}")
    
    # Output to arch subdirectory
    arch_output_dir = output_dir / arch
    output_zsig = arch_output_dir / f"vcruntime-vs{version}.zsig"
    
    if output_zsig.exists():
        print(f"Output already exists: {output_zsig}")
        print("Use --force to regenerate")
        return True
    
    return process_directory(
        dll_dir,
        output_zsig,
        prefix=f"vs{version}",
        version=version,
        arch=arch
    )


def main():
    parser = argparse.ArgumentParser(
        description="Generate r2 zignatures from Windows PE/DLL files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
    R2_DATA_DIR     Base directory for radare2 data (default: ~/.local/share/radare2)
                    DLLs read from $R2_DATA_DIR/cache/vcredist/
                    Zsigs written to $R2_DATA_DIR/zigns/windows/

Examples:
    %(prog)s --version 2022 --arch x64
    %(prog)s --dir /path/to/dlls -o runtime.zsig
    %(prog)s --dll vcruntime140.dll -o vcruntime.zsig
    %(prog)s --all
""",
    )
    
    parser.add_argument('--version', type=str, help="VS version (2022, 2019, etc)")
    parser.add_argument('--arch', type=str, help="Architecture (x64, x86, arm64)")
    parser.add_argument('--all', action='store_true', help="Process all cached versions")
    parser.add_argument('--dir', type=str, help="Directory containing DLL files")
    parser.add_argument('--dll', type=str, help="Process a single DLL file")
    parser.add_argument('-o', '--output', type=str, help="Output zsig path")
    parser.add_argument('--prefix', type=str, help="Signature prefix")
    parser.add_argument('--cache-dir', type=str, help="Override vcredist cache directory")
    parser.add_argument('--output-dir', type=str, help="Override zsig output directory")
    parser.add_argument('--force', action='store_true', help="Overwrite existing files")
    
    args = parser.parse_args()
    
    cache_dir = Path(args.cache_dir) if args.cache_dir else VCREDIST_CACHE_DIR
    output_dir = Path(args.output_dir) if args.output_dir else ZSIG_OUTPUT_DIR
    
    if args.dll:
        # Single DLL mode
        dll_path = Path(args.dll)
        if not dll_path.exists():
            print(f"Error: {dll_path} not found", file=sys.stderr)
            sys.exit(1)
        
        output = Path(args.output) if args.output else Path(f"{dll_path.stem}.zsig")
        
        if output.exists() and not args.force:
            print(f"Output already exists: {output}")
            print("Use --force to overwrite")
            sys.exit(0)
        
        success, _ = process_dll(dll_path, output, prefix=args.prefix)
        sys.exit(0 if success else 1)
    
    elif args.dir:
        # Directory mode
        dll_dir = Path(args.dir)
        if not dll_dir.exists():
            print(f"Error: {dll_dir} not found", file=sys.stderr)
            sys.exit(1)
        
        output = Path(args.output) if args.output else Path("vcruntime.zsig")
        
        if output.exists() and not args.force:
            print(f"Output already exists: {output}")
            print("Use --force to overwrite")
            sys.exit(0)
        
        success = process_directory(dll_dir, output, prefix=args.prefix)
        sys.exit(0 if success else 1)
    
    elif args.all:
        # Process all cached versions
        if not cache_dir.exists():
            print(f"Error: Cache directory not found: {cache_dir}", file=sys.stderr)
            print("Run: download-vcredist.py --all", file=sys.stderr)
            sys.exit(1)
        
        success = False
        for version_dir in sorted(cache_dir.iterdir()):
            if not version_dir.is_dir():
                continue
            version = version_dir.name
            
            for arch_dir in sorted(version_dir.iterdir()):
                if not arch_dir.is_dir():
                    continue
                arch = arch_dir.name
                
                if process_version(version, arch, cache_dir, output_dir):
                    success = True
        
        sys.exit(0 if success else 1)
    
    elif args.version and args.arch:
        # Specific version/arch mode
        success = process_version(args.version, args.arch, cache_dir, output_dir)
        sys.exit(0 if success else 1)
    
    elif args.version:
        # All archs for a version
        success = False
        for arch in ['x64', 'x86', 'arm64']:
            if find_vcredist_dir(args.version, arch, cache_dir):
                if process_version(args.version, arch, cache_dir, output_dir):
                    success = True
        sys.exit(0 if success else 1)
    
    elif args.arch:
        # All versions for an arch
        if not cache_dir.exists():
            print(f"Error: Cache directory not found: {cache_dir}", file=sys.stderr)
            sys.exit(1)
        
        success = False
        for version_dir in sorted(cache_dir.iterdir()):
            if not version_dir.is_dir():
                continue
            version = version_dir.name
            
            if find_vcredist_dir(version, args.arch, cache_dir):
                if process_version(version, args.arch, cache_dir, output_dir):
                    success = True
        
        sys.exit(0 if success else 1)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
