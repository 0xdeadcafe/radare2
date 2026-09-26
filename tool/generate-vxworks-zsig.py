#!/usr/bin/env python3
"""
Generate r2 zignatures from VxWorks 7 SDK static libraries.

Source: wrsdk-vxworks7-qemu-1.16.1 (VxWorks 25.09, LLVM 18.1.8.1)
Target: x86-64 VxWorks RTP + kernel

Processes usr/lib/common/*.a, krnl/llvm/*.a, and usr/3pp/develop/usr/lib/libsqlite3.a.
Skips libraries with fewer than 10 text symbols (stripped or headers-only).

Usage:
    generate-vxworks-zsig.py --sysroot /path/to/vxsdk/sysroot
    generate-vxworks-zsig.py --sysroot /path/to/vxsdk/sysroot --lib libc --lib libssl

Requirements:
    r2pipe, ar, nm (binutils)
"""
import argparse
import os
import sys
from pathlib import Path

# Make zsig_utils importable from same directory
sys.path.insert(0, str(Path(__file__).parent))
from zsig_utils import (
    require_tools,
    check_symbols,
    generate_zsig_from_lib,
    get_zsig_output_dir,
)

# VxWorks SDK version tag used in file headers / output paths
SDK_VERSION = "wrsdk-vxworks7-qemu-1.16.1"
VX_VERSION  = "25.09"

# Libraries to process, in priority order.
# Format: (relative_path_under_sysroot, output_zsig_stem, min_syms)
CORE_LIBS = [
    # Path under sysroot                                  zsig stem           min T syms
    ("usr/lib/common/libc.a",                             "vxworks7-libc",    20),
    ("usr/lib/common/libcrypto.a",                        "vxworks7-libcrypto", 20),
    ("usr/lib/common/libssl.a",                           "vxworks7-libssl",  20),
    ("usr/lib/common/libcurl.a",                          "vxworks7-libcurl", 20),
    ("usr/lib/common/libomp.a",                           "vxworks7-libomp",  20),
    ("usr/lib/common/libmosquitto.a",                     "vxworks7-libmosquitto", 10),
    ("usr/lib/common/libdl.a",                            "vxworks7-libdl",   10),
    ("usr/lib/common/libxml.a",                           "vxworks7-libxml",  10),
    ("usr/lib/common/libunix.a",                          "vxworks7-libunix", 10),
    ("usr/lib/common/libz.a",                             "vxworks7-libz",    10),
    ("usr/lib/common/libcjson.a",                         "vxworks7-libcjson", 10),
    ("usr/lib/common/libnet.a",                           "vxworks7-libnet",  10),
    ("usr/lib/common/libbz2.a",                           "vxworks7-libbz2",  10),
    ("usr/lib/common/libmbedtls_hash.a",                  "vxworks7-libmbedtls_hash", 10),
    ("usr/lib/common/libuuid.a",                          "vxworks7-libuuid", 10),
    ("krnl/llvm/libcplus.a",                              "vxworks7-libcplus-krnl", 10),
    ("usr/3pp/develop/usr/lib/libsqlite3.a",              "vxworks7-sqlite3", 20),
]


def process_lib(sysroot: Path, lib_rel: str, zsig_stem: str, min_syms: int,
                out_dir: Path) -> tuple[bool, int]:
    lib_path = sysroot / lib_rel
    if not lib_path.exists():
        print(f"  SKIP {lib_rel}: not found")
        return False, 0

    sym_count = check_symbols(str(lib_path))
    if sym_count < min_syms:
        print(f"  SKIP {lib_path.name}: {sym_count} T syms (threshold {min_syms})")
        return False, 0

    zsig_path = out_dir / f"{zsig_stem}.zsig"
    if zsig_path.exists():
        print(f"  SKIP {zsig_path.name}: already exists")
        return True, 0

    print(f"  {lib_path.name}: {sym_count} T syms -> {zsig_path.name} ...", end=" ", flush=True)
    success, sig_count = generate_zsig_from_lib(str(lib_path), str(zsig_path))
    if success:
        size = zsig_path.stat().st_size
        print(f"OK ({sig_count} sigs, {size:,} bytes)")
    else:
        print("FAIL")
    return success, sig_count


def main():
    require_tools(["ar", "nm"], install_hint="apt install binutils")

    parser = argparse.ArgumentParser(
        description=f"Generate VxWorks 7 ({VX_VERSION}) r2 zignatures from SDK static libs",
    )
    parser.add_argument("--sysroot", required=True,
                        help="Path to VxWorks SDK sysroot (vxsdk/sysroot)")
    parser.add_argument("--lib", action="append", metavar="STEM",
                        help="Only process lib with this zsig stem (repeatable); "
                             "e.g. --lib vxworks7-libc")
    parser.add_argument("--force", action="store_true",
                        help="Regenerate even if output zsig already exists")
    args = parser.parse_args()

    sysroot = Path(args.sysroot).resolve()
    if not sysroot.exists():
        print(f"Error: sysroot not found: {sysroot}", file=sys.stderr)
        sys.exit(1)

    out_dir = get_zsig_output_dir("vxworks/x86_64")
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output: {out_dir}")
    print(f"Source: {SDK_VERSION}  VxWorks {VX_VERSION}\n")

    filter_stems = set(args.lib) if args.lib else None

    total_ok = 0
    total_sigs = 0
    for lib_rel, zsig_stem, min_syms in CORE_LIBS:
        if filter_stems and zsig_stem not in filter_stems:
            continue

        if args.force:
            zsig_path = out_dir / f"{zsig_stem}.zsig"
            if zsig_path.exists():
                zsig_path.unlink()

        ok, sigs = process_lib(sysroot, lib_rel, zsig_stem, min_syms, out_dir)
        if ok:
            total_ok += 1
            total_sigs += sigs

    print(f"\nDone: {total_ok}/{len(CORE_LIBS)} libs, ~{total_sigs} total sigs")
    print(f"Load in r2: zo {out_dir}/<lib>.zsig")


if __name__ == "__main__":
    main()
