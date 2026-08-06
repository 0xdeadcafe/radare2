#!/usr/bin/env python3
"""
Generate r2 zignatures from uClibc-ng static libraries for AArch64 targets.

Downloads Bootlin pre-built aarch64/uclibc toolchain and generates a zsig file.
Source: https://toolchains.bootlin.com/downloads/releases/toolchains/aarch64/

Coverage:
  aarch64 uclibc-ng (Cortex-A53/A55/A72, ARMv8-A soft-float or hard-float)
  Typical targets: OpenWrt AArch64 (RPi 4/5, Rockchip RK35xx, Amlogic S905X)

Output:
  zigns/uclibc/arm64/uclibc-libc.zsig

Usage:
    generate-uclibc-arm64-zsig.py
    generate-uclibc-arm64-zsig.py --version 2024.02-1
    generate-uclibc-arm64-zsig.py --output-dir /tmp/test-zsigs
"""
import argparse
import os
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

from zsig_utils import get_zsig_output_dir

R2_DATA_DIR    = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
DOWNLOAD_CACHE = R2_DATA_DIR / "cache" / "uclibc-bootlin-arm64"
ZSIG_OUTPUT_DIR = get_zsig_output_dir("uclibc")

BOOTLIN_BASE = "https://toolchains.bootlin.com/downloads/releases/toolchains"
ARCH_DIR     = "aarch64"
TARBALL_RE   = re.compile(r"aarch64--uclibc--stable-([\d.]+(?:-\d+)?)\.tar\.bz2")
R2_SUBDIR    = "arm64"


def _find_latest_stable() -> str | None:
    url = f"{BOOTLIN_BASE}/{ARCH_DIR}/tarballs/"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            html = resp.read().decode(errors="replace")
    except Exception as exc:
        print(f"  Cannot fetch Bootlin index: {exc}", file=sys.stderr)
        return None
    versions = sorted(set(TARBALL_RE.findall(html)))
    return versions[-1] if versions else None


def _download_toolchain(version: str | None) -> Path | None:
    if version is None:
        print(f"  Discovering latest stable version for {ARCH_DIR} ...")
        version = _find_latest_stable()
        if version is None:
            print(f"  Cannot determine version for {ARCH_DIR}", file=sys.stderr)
            return None
        print(f"  Found version: {version}")

    tarball_name = f"{ARCH_DIR}--uclibc--stable-{version}.tar.bz2"
    tarball_path = DOWNLOAD_CACHE / tarball_name
    DOWNLOAD_CACHE.mkdir(parents=True, exist_ok=True)

    if tarball_path.exists():
        print(f"  Using cached: {tarball_path}")
        return tarball_path

    url = f"{BOOTLIN_BASE}/{ARCH_DIR}/tarballs/{tarball_name}"
    print(f"  Downloading {url} ...")
    try:
        urllib.request.urlretrieve(url, tarball_path)
    except Exception as exc:
        print(f"  Download failed: {exc}", file=sys.stderr)
        tarball_path.unlink(missing_ok=True)
        return None
    print(f"  Saved to {tarball_path} ({tarball_path.stat().st_size:,} bytes)")
    return tarball_path


def _extract_uclibc_libs(tarball_path: Path) -> Path | None:
    extract_dir = DOWNLOAD_CACHE / f"extracted-{ARCH_DIR}"
    libs_dir    = extract_dir / "libs"
    libs_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Extracting uClibc .a files from {tarball_path.name} ...")
    extracted = 0

    # Fast path: if libs_dir already has .a files, skip the tarball scan
    existing = list(libs_dir.glob("*.a"))
    if existing:
        print(f"  Using {len(existing)} cached .a files from {libs_dir}")
        return libs_dir
    # Exclude GCC runtime libraries that are not part of the C library:
    # libstdc++, libgfortran, libgomp, libstdc++fs have no relevance for
    # matching uClibc firmware binaries.
    # Also exclude *_pic.a variants — these are PIC duplicates of the main
    # archives (same functions, PIC relocations differ but sig bodies match).
    EXCLUDE_PREFIXES = ("libstdc", "libgfortran", "libgomp", "libsupc")
    try:
        with tarfile.open(tarball_path, "r:bz2") as tf:
            for member in tf.getmembers():
                name = member.name
                basename = Path(name).name
                # Sysroot static libs only; skip GCC-internal archives,
                # non-libc GCC runtime libraries, and _pic.a duplicates
                if (name.endswith(".a")
                        and "/sysroot/usr/lib/" in name
                        and "/usr/lib/gcc/" not in name
                        and not basename.endswith("_pic.a")
                        and not any(basename.startswith(p) for p in EXCLUDE_PREFIXES)):
                    dest = libs_dir / basename
                    if dest.exists():
                        continue
                    fobj = tf.extractfile(member)
                    if fobj:
                        dest.write_bytes(fobj.read())
                        extracted += 1
    except Exception as exc:
        print(f"  Extraction error: {exc}", file=sys.stderr)
        return None

    if extracted == 0:
        print(f"  No .a files found in {tarball_path.name}", file=sys.stderr)
        return None

    print(f"  Extracted {extracted} .a files to {libs_dir}")
    return libs_dir


def _prune_zsig(zsig_path: Path) -> int:
    """Remove fcn.*, Fortran, and OpenMP entries using strings(1) + rasign2.

    Avoids r2pipe 'zj' which times out for large (>10K entry) zsig files.
    Returns count of kept entries.
    """
    import r2pipe as _r2pipe, subprocess as _sp, shutil as _sh, json as _js

    # Read entries via strings(1) -- fast and doesn't require r2pipe session
    result = _sp.run(["strings", str(zsig_path)], capture_output=True, text=True)
    raw_entries = [
        l for l in result.stdout.splitlines() if l.startswith("zign|")
    ]

    # Parse: zign|<type>|<name>|...
    def _name(line: str) -> str:
        parts = line.split("|", 3)
        return parts[2] if len(parts) >= 3 else ""

    def _keep(name: str) -> bool:
        if not name or name.startswith(("fcn.", "sub.", "entry")):
            return False
        if name.startswith(("_gfortran_", "GOMP_", "gomp_", "GOACC_", "inquire_")):
            return False
        return True

    kept_names = {_name(l) for l in raw_entries if _keep(_name(l))}
    total      = len(raw_entries)
    kept_count = len(kept_names)
    removed    = total - kept_count

    if removed == 0:
        return kept_count

    print(f"  Pruning {removed} non-libc entries ({kept_count} kept) ...")

    # Load full zsig in r2, keep only wanted names, save
    # Use rasign2 -A approach: load zsig, filter by name with zo + za
    tmp = str(zsig_path) + ".prune_tmp"
    r2 = _r2pipe.open("malloc://1", flags=["-e", "scr.color=0", "-2"])
    r2.cmd(f"zo {zsig_path}")
    # zf (filter) is not available; use zd (delete by name) on unwanted entries
    # For large sets, batch-delete is faster than batch-keep
    # Get all names via 'z~?'/listing and delete those NOT in kept_names
    # Better: save all, reload, delete unwanted
    all_names_raw = r2.cmd("z")  # one line per sig: "zign name ..."
    r2.quit()

    # Parse 'z' output: first field after 'zign ' is the name
    all_names = set()
    for line in all_names_raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "zign":
            all_names.add(parts[1])

    unwanted = all_names - kept_names

    if not unwanted:
        return kept_count

    # Rebuild: load zsig, remove unwanted, save
    r2b = _r2pipe.open("malloc://1", flags=["-e", "scr.color=0", "-2"])
    r2b.cmd(f"zo {zsig_path}")
    for name in unwanted:
        r2b.cmd(f'z- "{name}"')
    r2b.cmd(f"zos {tmp}")
    r2b.quit()

    from pathlib import Path as _P
    if _P(tmp).exists() and _P(tmp).stat().st_size > 0:
        _sh.move(tmp, zsig_path)
        # Count actual kept entries
        res = _sp.run(["strings", str(zsig_path)], capture_output=True, text=True)
        return sum(1 for l in res.stdout.splitlines() if l.startswith("zign|"))
    return kept_count


def generate(version: str | None = None, output_dir: Path | None = None) -> bool:
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    print(f"\n=== uClibc-ng AArch64 ===")

    tarball = _download_toolchain(version)
    if not tarball:
        return False

    libs_dir = _extract_uclibc_libs(tarball)
    if not libs_dir:
        return False

    output_path = output_dir / R2_SUBDIR / "uclibc-libc.zsig"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate zsig only from .os objects that have NAMED text symbols.
    # This pre-filter prevents anonymous helper functions (42K fcn.* entries)
    # from contaminating the zsig with noise.
    import tempfile, subprocess as _sp
    from zsig_utils import (
        extract_objects_from_archive,
        _generate_zsig_from_object,
    )

    libc_a = libs_dir / "libc.a"
    if not libc_a.exists():
        print(f"  ERROR: libc.a not found in {libs_dir}", file=sys.stderr)
        return False

    print(f"  Filtering named-symbol objects from {libc_a.name} ...")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        obj_files = extract_objects_from_archive(str(libc_a), tmp)

        # Keep only objects with at least one named text symbol
        named_objs = []
        for obj in obj_files:
            r = _sp.run(["nm", obj], capture_output=True, text=True)
            # Named text symbol: line has 3 fields, type is T/t, name is not
            # a hex string (i.e. has letters beyond a-f)
            has_named = any(
                len(parts) == 3
                and parts[1] in ("T", "t")
                and not all(c in "0123456789abcdefABCDEF" for c in parts[2])
                for parts in (l.split() for l in r.stdout.splitlines())
            )
            if has_named:
                named_objs.append(obj)

        print(f"  {len(named_objs)}/{len(obj_files)} objects have named symbols")

        # Generate zsig per object in batches (merge_zsigs with 1000+ files overflows r2)
        from zsig_utils import generate_zsig_batch
        ok, sig_count = generate_zsig_batch(
            named_objs,
            str(output_path),
            prefix="uclibc",
            batch_size=80,
            log=print,
        )

    if ok:
        # Count actual entries (not z~? which overcounts SDB lines)
        r = _sp.run(["strings", str(output_path)], capture_output=True, text=True)
        actual = sum(1 for l in r.stdout.splitlines() if l.startswith("zign|"))
        named_pct = int(100 * sum(
            1 for l in r.stdout.splitlines()
            if l.startswith("zign|") and len(l.split("|")) >= 3
            and not l.split("|")[2].startswith(("fcn.", "sub."))
        ) / max(actual, 1))
        print(f"\n  Output: {output_path}")
        print(f"  {actual} sigs  {named_pct}% named  {output_path.stat().st_size:,} bytes")
    else:
        print("  zsig generation failed")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--version",
                    help="Bootlin release tag (e.g. 2024.02-1); auto-discovered if omitted")
    ap.add_argument("--output-dir",
                    help=f"Override zsig output directory (default: {ZSIG_OUTPUT_DIR})")
    args = ap.parse_args()

    out = Path(args.output_dir) if args.output_dir else None
    if not generate(args.version, out):
        sys.exit(1)


if __name__ == "__main__":
    main()
