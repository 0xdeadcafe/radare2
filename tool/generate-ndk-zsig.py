#!/usr/bin/env python3
"""
Generate r2 zignatures from Android NDK static libraries.

This script downloads NDK packages, extracts static libraries (libc.a, libm.a, etc.),
and generates zsig files for function recognition in stripped Android native binaries.

Requirements:
    - Python 3.8+
    - r2pipe (pip install r2pipe)
    - ar, nm (binutils)

Usage:
    generate-ndk-zsig.py --arch arm64-v8a          # Generate for arm64
    generate-ndk-zsig.py --all                     # Generate for all architectures
    generate-ndk-zsig.py --list                    # List available architectures
    generate-ndk-zsig.py --use-local --arch arm64  # Use existing ANDROID_NDK_HOME
"""
import argparse
import os
import sys
import tempfile
from pathlib import Path

from zsig_utils import (
    run,
    check_symbols,
    extract_objects_from_archive,
    generate_zsig_batch,
    merge_zsigs,
    get_zsig_output_dir,
)

try:
    import r2pipe
except ImportError:
    print("Error: r2pipe not installed. Run: pip install r2pipe", file=sys.stderr)
    sys.exit(1)

# Import our download helper
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

# Import with underscore since file uses hyphens
import importlib.util
spec = importlib.util.spec_from_file_location("download_android_ndk", SCRIPT_DIR / "download-android-ndk.py")
download_android_ndk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(download_android_ndk)

download_ndk = download_android_ndk.download_ndk
ARCH_MAP = download_android_ndk.ARCH_MAP
ABI_ALIASES = download_android_ndk.ABI_ALIASES
DEFAULT_VERSION = download_android_ndk.DEFAULT_VERSION
NDK_VERSIONS = download_android_ndk.NDK_VERSIONS

# Output directory for zsigs
ZSIG_OUTPUT_DIR = get_zsig_output_dir("android")


# Key libraries to process (in order of importance)
KEY_LIBS = [
    "libc.a",               # Bionic C library - most important
    "libm.a",               # Math library
    "libc++_static.a",      # C++ standard library
    "libc++abi.a",          # C++ ABI support
]


def generate_lib_zsig(lib_path: Path, output_path: Path, prefix: str,
                      log=None) -> tuple[bool, int]:
    """Generate zsig for a single library file."""
    if log is None:
        log = print

    log(f"  Processing: {lib_path.name}")
    
    # Check symbol count
    sym_count = check_symbols(str(lib_path))
    log(f"    Symbols: {sym_count}")
    
    if sym_count < 5:
        log(f"    SKIP: too few symbols (stripped?)")
        return False, 0
    
    # Extract objects
    with tempfile.TemporaryDirectory() as work_dir:
        objects = extract_objects_from_archive(str(lib_path), work_dir)
        if not objects:
            log(f"    SKIP: no objects extracted")
            return False, 0
        
        log(f"    Objects: {len(objects)}")
        
        # Generate zsig
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        success, sig_count = generate_zsig_batch(
            objects, 
            str(output_path), 
            prefix=prefix,
            log=log
        )
        
        if success:
            size = output_path.stat().st_size
            log(f"    Output: {output_path.name} ({size:,} bytes, {sig_count} signatures)")
            return True, sig_count
        else:
            log(f"    FAILED to generate zsig")
            return False, 0


def generate_ndk_zsig(abi: str, version: str = DEFAULT_VERSION, output_dir: Path = None,
                      use_local: bool = False, log=None) -> tuple[bool, dict]:
    """Generate zsigs for an Android ABI."""
    if log is None:
        log = print

    # Resolve ABI aliases
    if abi in ABI_ALIASES:
        abi = ABI_ALIASES[abi]
    
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    
    # Download/extract NDK libraries
    log(f"\n{'='*60}")
    log(f"Generating NDK zsigs for {abi}")
    log(f"{'='*60}")
    
    lib_dir = download_ndk(version, abi, use_local=use_local)
    if not lib_dir:
        log(f"Failed to get NDK libraries for {abi}")
        return False, {"libraries_processed": 0, "libraries_skipped": 0, "total_signatures": 0}
    
    log(f"\nLibrary directory: {lib_dir}")
    
    # Find all .a files
    all_libs = list(lib_dir.glob("*.a"))
    if not all_libs:
        log(f"No .a files found in {lib_dir}")
        return False, {"libraries_processed": 0, "libraries_skipped": 0, "total_signatures": 0}

    log(f"Found {len(all_libs)} libraries")
    
    # Process key libraries first, then others
    processed = []
    skipped = []
    zsig_parts = []
    total_sigs = 0
    
    # Sort: key libs first, then others alphabetically
    def sort_key(lib_path):
        name = lib_path.name
        if name in KEY_LIBS:
            return (0, KEY_LIBS.index(name))
        return (1, name)
    
    all_libs.sort(key=sort_key)
    
    with tempfile.TemporaryDirectory() as merge_dir:
        for i, lib_path in enumerate(all_libs):
            lib_name = lib_path.name
            
            # Progress indicator to stdout
            print(f"  [{i+1}/{len(all_libs)}] {lib_name}...", end=" ", flush=True)
            
            # Clean name for zsig prefix (remove lib prefix and .a suffix)
            prefix_name = lib_name
            if prefix_name.startswith("lib"):
                prefix_name = prefix_name[3:]
            if prefix_name.endswith(".a"):
                prefix_name = prefix_name[:-2]
            prefix = f"ndk_{prefix_name}"
            
            zsig_path = Path(merge_dir) / f"{lib_name}.zsig"
            
            success, sig_count = generate_lib_zsig(lib_path, zsig_path, prefix, log=log)
            if success:
                zsig_parts.append(str(zsig_path))
                processed.append(lib_name)
                total_sigs += sig_count
                print(f"done ({sig_count} sigs)")
            else:
                skipped.append(lib_name)
                print("skipped")
    
        if not zsig_parts:
            log(f"\nNo zsigs generated for {abi}")
            return False, {"libraries_processed": 0, "libraries_skipped": len(skipped), "total_signatures": 0}
        
        # Create combined zsig
        log(f"\n  Creating combined zsig...")
        combined_output = output_dir / abi / f"ndk-{version}.zsig"
        combined_output.parent.mkdir(parents=True, exist_ok=True)
        
        success, final_count = merge_zsigs(zsig_parts, str(combined_output))
        
        stats = {
            "libraries_processed": len(processed),
            "libraries_skipped": len(skipped),
            "total_signatures": final_count if final_count > 0 else total_sigs,
            "output_path": str(combined_output),
        }
        
        if success and combined_output.exists():
            size = combined_output.stat().st_size
            log(f"\n  Combined output: {combined_output}")
            log(f"  Size: {size:,} bytes")
            log(f"  Signatures: {stats['total_signatures']:,}")
            log(f"  Libraries included: {', '.join(processed)}")
            if skipped:
                log(f"  Libraries skipped: {', '.join(skipped)}")
            print(f"  Libraries: {len(processed)}, Signatures: {stats['total_signatures']:,}")
            return True, stats
        else:
            log(f"\n  Failed to create combined zsig")
            return False, stats


def list_available():
    """List available architectures and versions."""
    print("Android NDK zsig generator")
    print()
    print("Available NDK versions:")
    for version in NDK_VERSIONS:
        default = " (default)" if version == DEFAULT_VERSION else ""
        print(f"  {version}{default}")
    
    print()
    print("Target architectures (ABIs):")
    for abi, triple in ARCH_MAP.items():
        aliases = [k for k, v in ABI_ALIASES.items() if v == abi]
        alias_str = f" (aliases: {', '.join(aliases)})" if aliases else ""
        print(f"  {abi:15} -> {triple}{alias_str}")
    
    print()
    print("Key libraries processed:")
    for lib in KEY_LIBS:
        print(f"  - {lib}")
    
    print()
    print(f"Output directory: {ZSIG_OUTPUT_DIR}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate r2 zignatures from Android NDK static libraries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
    ANDROID_NDK_HOME    Path to existing NDK installation (use with --use-local)

Examples:
    %(prog)s --arch arm64-v8a          # Generate for arm64
    %(prog)s --arch arm64              # Same (alias)
    %(prog)s --all                     # Generate for all architectures
    %(prog)s --list                    # List available architectures
    %(prog)s --use-local --arch arm64  # Use existing ANDROID_NDK_HOME
    %(prog)s --version r26d --all      # Use specific NDK version
""",
    )
    
    parser.add_argument("--list", action="store_true", help="List available architectures")
    parser.add_argument("--all", action="store_true", help="Generate for all architectures")
    parser.add_argument("--arch", type=str, help=f"Target ABI ({', '.join(ARCH_MAP.keys())})")
    parser.add_argument("--version", type=str, default=DEFAULT_VERSION, 
                        help=f"NDK version (default: {DEFAULT_VERSION})")
    parser.add_argument("--use-local", action="store_true", 
                        help="Use existing ANDROID_NDK_HOME instead of downloading")
    parser.add_argument("--output-dir", type=str, help="Output directory (overrides default)")
    
    args = parser.parse_args()
    
    if args.list:
        list_available()
        return
    
    if not args.all and not args.arch:
        parser.print_help()
        sys.exit(1)
    
    output_dir = ZSIG_OUTPUT_DIR
    if args.output_dir:
        output_dir = Path(args.output_dir)

    log_path = output_dir / "generate-ndk-zsig.log"
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Log: {log_path}")

    def log(msg: str):
        print(msg)
        with open(log_path, "a") as f:
            f.write(msg + "\n")

    if args.all:
        success = 0
        total_sigs = 0
        all_stats = []
        for abi in ARCH_MAP:
            ok, stats = generate_ndk_zsig(abi, args.version, output_dir, args.use_local, log=log)
            if ok:
                success += 1
                total_sigs += stats.get("total_signatures", 0)
            all_stats.append((abi, ok, stats))
        print(f"\n{'='*60}")
        print(f"Generated {success}/{len(ARCH_MAP)} zsigs")
        print(f"Total signatures: {total_sigs:,}")
        print(f"{'='*60}")
        for abi, ok, stats in all_stats:
            status = "OK" if ok else "FAILED"
            sigs = stats.get("total_signatures", 0)
            libs = stats.get("libraries_processed", 0)
            print(f"  {abi:15} {status:6} {libs:3} libs, {sigs:,} sigs")
    else:
        arch = args.arch
        if arch in ABI_ALIASES:
            arch = ABI_ALIASES[arch]
        if arch not in ARCH_MAP:
            print(f"Unknown architecture: {args.arch}", file=sys.stderr)
            print(f"Available: {', '.join(list(ARCH_MAP.keys()) + list(ABI_ALIASES.keys()))}", file=sys.stderr)
            sys.exit(1)
        ok, stats = generate_ndk_zsig(arch, args.version, output_dir, args.use_local, log=log)
        if not ok:
            sys.exit(1)

    print(f"\nLog: {log_path}")


if __name__ == "__main__":
    main()
