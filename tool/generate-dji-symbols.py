#!/usr/bin/env python3
"""
Generate r2 symbol scripts from DJI symbol .map files.

DJI firmware symbol maps (IAR linker format) contain function names and
addresses from reverse engineering work. This tool converts them to
r2 scripts that define flags (symbols) at known addresses.

Usage:
    ./generate-dji-symbols.py <symbols_dir> <output_dir>
    ./generate-dji-symbols.py --single <map_file> <output.r2>

Examples:
    ./generate-dji-symbols.py ~/dji-tools/symbols/ ./symbols/dji/
    ./generate-dji-symbols.py --single P3X_FW_V01.07.0060_m0306.map flyc.r2

Applying symbols:
    r2 -i symbols/dji/flyc/P3X_V01.07.0060.r2 firmware.bin

Output Format:
    This tool generates r2 scripts with flag definitions (f NAME @ ADDR).
    These are address-based symbol definitions that only work when the
    binary is loaded at the correct base address.

    For pattern-matching signatures that work across firmware versions,
    you need both the map file AND the matching firmware binary. See
    "Generating Byte-Pattern Signatures" below.

Generating Byte-Pattern Signatures:
    If you have BOTH a .map file AND the matching firmware binary, you can
    generate true byte-pattern zignatures that match across similar binaries:

    1. Apply symbols to firmware:
       r2 -i symbols.r2 firmware.bin

    2. Generate zignatures from analyzed functions:
       [0x00000000]> aaa              # analyze all
       [0x00000000]> zg               # generate zsigs from functions
       [0x00000000]> zos output.zsig  # save signatures

    Or as a one-liner:
       r2 -q -c '. symbols.r2; aaa; e zign.prefix=dji_flyc; zg; zos out.zsig' fw.bin

    The resulting .zsig file contains byte patterns that can match functions
    even in different firmware versions (with some variance tolerance).

    Required files for each platform:
    - Map file: Contains symbol names and addresses (from RE work)
    - Firmware: The actual binary matching that specific version
    
    Firmware sources:
    - DJI official downloads (older versions)
    - Extracted from .bin update packages using dji-firmware-tools
    - Module extraction: Use arm_bin2elf.py or amba_sys2elf.py

    Module numbers (mXXXX in filenames):
    - m0100: Ambarella camera system
    - m0306: Flight controller (STM32)
    - m0800: DM3xx video encoder
    - m0900: Lightbridge STM32
    - m1300: OFDM modem
    - m1400/m1401: Gimbal controller
"""

import argparse
import os
import re
import sys
from pathlib import Path


def parse_iar_map(map_path: str, min_name_len: int = 3) -> list[tuple[int, str]]:
    """Parse IAR linker .map file to extract code symbols.
    
    IAR map format:
        0001:XXXXXXXX       symbol_name
        
    Where 0001 is the .text segment and XXXXXXXX is the address.
    
    Filters out:
    - Very short names (< min_name_len chars)
    - All uppercase names (likely constants)
    - IDA string literals (aXxxXxx pattern)
    - IDA null functions (nullsub_N)
    
    Args:
        map_path: Path to .map file
        min_name_len: Minimum symbol name length (default: 3)
        
    Returns:
        List of (address, symbol_name) tuples, sorted by address
    """
    symbols = []
    code_segment = None
    
    # IDA string literal pattern: aXxxxx where second char is uppercase
    string_pattern = re.compile(r'^a[A-Z][a-zA-Z0-9_]*$')
    
    # First pass: find which segment is .text (CODE)
    # Format: " 0001:00000000 000085D34H .text                  CODE"
    segment_pattern = re.compile(r'^\s+([0-9a-fA-F]{4}):([0-9a-fA-F]+)\s+[0-9a-fA-F]+H\s+\.text\s+CODE')
    
    try:
        with open(map_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\r\n')
                match = segment_pattern.match(line)
                if match:
                    code_segment = match.group(1)
                    break
    except Exception as e:
        print(f"Error reading {map_path}: {e}", file=sys.stderr)
        return []
    
    if code_segment is None:
        # Default to 0001 if not found
        code_segment = '0001'
    
    # Match code section symbols: " XXXX:XXXXXXXX       symbol_name"
    # Skip section headers (have size like 000085D34H after address)
    pattern = re.compile(rf'^\s+{code_segment}:([0-9a-fA-F]{{8}})\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*$')
    
    try:
        with open(map_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\r\n')
                match = pattern.match(line)
                if match:
                    addr = int(match.group(1), 16)
                    name = match.group(2)
                    
                    # Filter: skip short names
                    if len(name) < min_name_len:
                        continue
                    
                    # Filter: skip all uppercase (constants/defines)
                    if name.isupper():
                        continue
                    
                    # Filter: skip IDA null functions
                    if name.startswith('nullsub_'):
                        continue
                    
                    # Filter: skip IDA string literals
                    if string_pattern.match(name):
                        continue
                    
                    # Allow names with underscores (real functions like arm_xxx)
                    # Skip aXxx without underscore (likely IDA strings)
                    if name.startswith('a') and len(name) > 1 and name[1].islower():
                        if '_' not in name:
                            continue
                    
                    symbols.append((addr, name))
    except Exception as e:
        print(f"Error reading {map_path}: {e}", file=sys.stderr)
        return []
    
    # Sort by address and remove duplicates
    symbols = sorted(set(symbols), key=lambda x: x[0])
    return symbols


def generate_r2_script(symbols: list[tuple[int, str]], prefix: str) -> str:
    """Generate r2 script content with flag definitions.
    
    Creates an r2 script that:
    - Defines flags (symbols) at known addresses
    - Optionally defines functions for analysis
    
    Args:
        symbols: List of (address, name) tuples
        prefix: Symbol prefix (e.g., 'dji_flyc')
        
    Returns:
        r2 script content as string
    """
    lines = [
        "# DJI firmware symbols",
        f"# Prefix: {prefix}",
        f"# Symbols: {len(symbols)}",
        "# Usage: r2 -i <this_file> <firmware.bin>",
        "",
        "# Create flagspace for DJI symbols",
        f"fs {prefix}",
        "",
    ]
    
    for addr, name in symbols:
        # Sanitize name for r2 (replace problematic chars)
        safe_name = name.replace('.', '_').replace('-', '_')
        flag_name = f"{prefix}.{safe_name}"
        
        # Define flag at address
        lines.append(f"f {flag_name} @ 0x{addr:08x}")
    
    lines.append("")
    lines.append("# Switch back to default flagspace")
    lines.append("fs *")
    
    return '\n'.join(lines) + '\n'


def classify_map_file(filename: str) -> tuple[str, str]:
    """Classify a .map file into category and version.
    
    Examples:
        P3X_FW_V01.07.0060_m0306.map -> ('flyc', 'P3X_V01.07.0060')
        wm220_0306_v03.02.35.05.map -> ('flyc', 'wm220_v03.02.35.05')
        P3X_FW_V01.04.0005_m0900.map -> ('lightbridge', 'P3X_V01.04.0005')
        P3X_FW_V01.08.0080_m0100_part_sys.map -> ('amba_sys', 'P3X_V01.08.0080')
        C1_FW_V01.05.0080_m1400.map -> ('gimbal', 'C1_V01.05.0080')
    
    Args:
        filename: Map filename (without path)
        
    Returns:
        Tuple of (category, version_string)
    """
    stem = Path(filename).stem
    
    # Module type from filename
    if '_m0306' in stem or '_0306_' in stem:
        category = 'flyc'  # Flight Controller
    elif '_m0900' in stem:
        category = 'lightbridge'  # Lightbridge STM32
    elif '_m0100' in stem or '_part_sys' in stem:
        category = 'amba_sys'  # Ambarella system
    elif '_m0800' in stem or 'encode_usb' in stem:
        category = 'encode_usb'  # DM3xx encoder
    elif '_m1400' in stem or '_m1401' in stem:
        category = 'gimbal'  # Gimbal controller
    elif '_m1300' in stem:
        category = 'ofdm'  # OFDM module
    else:
        category = 'misc'
    
    # Extract version
    # Pattern: XX_FW_Vxx.xx.xxxx or XX_xxxx_vxx.xx.xx.xx
    version_match = re.search(r'([A-Z0-9]+)_(?:FW_)?(V?\d+[\.\d]+)', stem, re.IGNORECASE)
    if version_match:
        platform = version_match.group(1)
        version = version_match.group(2)
        version_str = f"{platform}_{version}"
    else:
        version_str = stem
    
    return category, version_str


def process_single_map(map_path: str, output_path: str, prefix: str = None) -> bool:
    """Process a single .map file to r2 script.
    
    Args:
        map_path: Path to input .map file
        output_path: Path for output .r2 script
        prefix: Optional symbol prefix
        
    Returns:
        True if successful
    """
    map_name = Path(map_path).stem
    
    if prefix is None:
        category, version = classify_map_file(Path(map_path).name)
        prefix = f"dji_{category}"
    else:
        category, version = classify_map_file(Path(map_path).name)
    
    print(f"Processing {map_name}...")
    
    symbols = parse_iar_map(map_path)
    if not symbols:
        print(f"  No symbols found", file=sys.stderr)
        return False
    
    print(f"  Found {len(symbols)} symbols")
    
    content = generate_r2_script(symbols, prefix)
    
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(content)
    
    print(f"  Wrote {output_path} ({len(symbols)} symbols)")
    return True


def process_directory(symbols_dir: str, output_dir: str) -> dict[str, list[str]]:
    """Process all .map files in a directory.
    
    Organizes output by category:
        output_dir/flyc/P3X_V01.07.0060.r2
        output_dir/lightbridge/P3X_V01.04.0005.r2
        etc.
    
    Args:
        symbols_dir: Directory containing .map files
        output_dir: Output directory for r2 scripts
        
    Returns:
        Dict mapping category to list of output files
    """
    map_files = list(Path(symbols_dir).glob('*.map'))
    if not map_files:
        print(f"No .map files found in {symbols_dir}", file=sys.stderr)
        return {}
    
    print(f"Found {len(map_files)} .map files")
    
    results = {}
    
    for map_path in sorted(map_files):
        category, version = classify_map_file(map_path.name)
        
        output_subdir = os.path.join(output_dir, category)
        output_file = os.path.join(output_subdir, f"{version}.r2")
        
        prefix = f"dji_{category}"
        
        if process_single_map(str(map_path), output_file, prefix):
            if category not in results:
                results[category] = []
            results[category].append(output_file)
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Generate r2 symbol scripts from DJI symbol .map files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--single', action='store_true',
                       help='Process single file instead of directory')
    parser.add_argument('--prefix', '-p', 
                       help='Symbol prefix (default: auto-detect)')
    parser.add_argument('input', help='Input .map file or symbols directory')
    parser.add_argument('output', help='Output .r2 script or directory')
    
    args = parser.parse_args()
    
    if args.single:
        if not os.path.isfile(args.input):
            print(f"Error: {args.input} is not a file", file=sys.stderr)
            sys.exit(1)
        success = process_single_map(args.input, args.output, args.prefix)
        sys.exit(0 if success else 1)
    else:
        if not os.path.isdir(args.input):
            print(f"Error: {args.input} is not a directory", file=sys.stderr)
            sys.exit(1)
        
        results = process_directory(args.input, args.output)
        
        if results:
            print(f"\nSummary:")
            total = 0
            for category, files in sorted(results.items()):
                print(f"  {category}: {len(files)} files")
                total += len(files)
            print(f"  Total: {total} r2 scripts generated")
        else:
            print("No zsig files generated", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
