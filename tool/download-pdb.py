#!/usr/bin/env python3
"""
Download PDB symbol files from Microsoft symbol server.

This tool extracts debug GUID from Windows PE files (DLL/EXE) and downloads
matching PDB files from Microsoft's public symbol server.

Usage:
    download-pdb.py <dll_or_exe_path> [--output-dir <dir>]
    download-pdb.py --batch <directory> [--output-dir <dir>]

Requirements:
    - radare2 (for extracting debug info from PE files)
    - Internet access to msdl.microsoft.com
"""
import argparse
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
DEFAULT_CACHE_DIR = Path.home() / ".local/share/radare2/cache/pdb"


def get_pe_debug_info(pe_path: str) -> tuple[str, str] | None:
    """
    Extract PDB filename and debug GUID from a PE file using radare2.
    
    Returns:
        Tuple of (pdb_filename, guid) or None if not found
    """
    try:
        result = subprocess.run(
            ["r2", "-qc", "iI~dbg_file,guid", pe_path],
            capture_output=True,
            timeout=30
        )
        if result.returncode != 0:
            return None
        
        output = result.stdout.decode("utf-8", errors="replace")
        
        pdb_file = None
        guid = None
        
        for line in output.splitlines():
            if line.startswith("dbg_file"):
                pdb_file = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else None
            elif line.startswith("guid"):
                guid = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else None
        
        if pdb_file and guid:
            return (pdb_file, guid)
        return None
        
    except Exception as e:
        print(f"  Error reading PE debug info: {e}", file=sys.stderr)
        return None


def download_pdb(pdb_name: str, guid: str, output_dir: Path) -> Path | None:
    """
    Download a PDB file from Microsoft symbol server.
    
    The URL format is:
        https://msdl.microsoft.com/download/symbols/<pdb_name>/<guid>/<pdb_name>
    
    Returns:
        Path to downloaded file or None on failure
    """
    url = f"{SYMBOL_SERVER}/{pdb_name}/{guid}/{pdb_name}"
    output_path = output_dir / pdb_name
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
            with open(output_path, "wb") as f:
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
        return output_path
        
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"  PDB not found on symbol server: {pdb_name}", file=sys.stderr)
        else:
            print(f"  HTTP error {e.code}: {e.reason}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Download failed: {e}", file=sys.stderr)
        return None


def process_pe_file(pe_path: Path, output_dir: Path) -> Path | None:
    """
    Process a single PE file: extract debug info and download PDB.
    
    Returns:
        Path to downloaded PDB or None
    """
    debug_info = get_pe_debug_info(str(pe_path))
    if not debug_info:
        return None
    
    pdb_name, guid = debug_info
    
    # Check if already downloaded
    output_path = output_dir / pdb_name
    if output_path.exists():
        return output_path
    
    return download_pdb(pdb_name, guid, output_dir)


def find_pe_files(directory: Path) -> list[Path]:
    """Find all DLL and EXE files in a directory."""
    pe_files = []
    for ext in ("*.dll", "*.exe", "*.DLL", "*.EXE"):
        pe_files.extend(directory.rglob(ext))
    return sorted(pe_files)


def main():
    parser = argparse.ArgumentParser(
        description="Download PDB symbol files from Microsoft symbol server"
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Path to DLL/EXE file"
    )
    parser.add_argument(
        "--batch",
        metavar="DIR",
        help="Process all DLL/EXE files in directory"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"Output directory for PDB files (default: {DEFAULT_CACHE_DIR})"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )
    
    args = parser.parse_args()
    
    if not args.input and not args.batch:
        parser.error("Either <input> or --batch is required")
    
    # Collect PE files to process
    pe_files: list[Path] = []
    
    if args.batch:
        batch_dir = Path(args.batch)
        if not batch_dir.is_dir():
            print(f"Error: {args.batch} is not a directory", file=sys.stderr)
            sys.exit(1)
        pe_files = find_pe_files(batch_dir)
        if not pe_files:
            print(f"No DLL/EXE files found in {args.batch}", file=sys.stderr)
            sys.exit(1)
    else:
        input_path = Path(args.input)
        if not input_path.is_file():
            print(f"Error: {args.input} not found", file=sys.stderr)
            sys.exit(1)
        pe_files = [input_path]
    
    # Process each file
    downloaded = 0
    skipped = 0
    failed = 0
    
    for pe_path in pe_files:
        if not args.quiet:
            print(f"Processing: {pe_path.name}")
        
        debug_info = get_pe_debug_info(str(pe_path))
        if not debug_info:
            if not args.quiet:
                print(f"  No debug info found")
            skipped += 1
            continue
        
        pdb_name, guid = debug_info
        output_path = args.output_dir / pdb_name
        
        # Skip if already downloaded
        if output_path.exists():
            if not args.quiet:
                print(f"  Already have: {pdb_name}")
            downloaded += 1
            continue
        
        if not args.quiet:
            print(f"  Downloading: {pdb_name} ({guid})")
        
        result = download_pdb(pdb_name, guid, args.output_dir)
        if result:
            if not args.quiet:
                size = result.stat().st_size
                print(f"  Downloaded: {size:,} bytes")
            downloaded += 1
        else:
            failed += 1
    
    # Summary
    if not args.quiet:
        print()
        print(f"Summary: {downloaded} downloaded, {skipped} skipped (no debug info), {failed} failed")
    
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
