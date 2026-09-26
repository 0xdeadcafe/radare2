#!/usr/bin/env python3
"""
Generate r2 zignatures from Debian/Ubuntu library packages.

Downloads .deb packages from the Ubuntu 22.04 (jammy) repository for the
requested architecture(s), extracts static libraries, and generates zsig
files for function recognition in stripped binaries.

Coverage: 23 library zsig targets across amd64, arm64, armhf, i386.
Package URLs are resolved dynamically from the Ubuntu Packages.gz index so
version pinning is not needed -- the latest security-patched version is
always used.

Requirements:
    - Python 3.8+, r2pipe (pip install r2pipe)
    - ar, nm, dpkg-deb (apt install binutils dpkg)

Usage:
    generate-debian-libs-zsig.py --arch armhf
    generate-debian-libs-zsig.py --arch i386
    generate-debian-libs-zsig.py --arch arm64   # fills 2 missing zsigs
    generate-debian-libs-zsig.py --all-arches
    generate-debian-libs-zsig.py --list
    generate-debian-libs-zsig.py --arch armhf --force   # regenerate existing
"""
import argparse
import fnmatch
import gzip
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR  = Path(__file__).parent
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR",
                   Path.home() / ".local" / "share" / "radare2"))
ZSIG_OUT_DIR = R2_DATA_DIR / "zigns" / "debian"
CACHE_DIR    = R2_DATA_DIR / "cache" / "debian-libs"

# ---------------------------------------------------------------------------
# Ubuntu 22.04 (jammy) repository configuration
# Suite priority: later entries override earlier ones (security/updates win).
# ---------------------------------------------------------------------------
SUITE_PRIORITY = ["jammy", "jammy-updates", "jammy-security"]

REPO_ROOTS = {
    "amd64": "http://archive.ubuntu.com/ubuntu",
    "arm64": "http://ports.ubuntu.com/ubuntu-ports",
    "armhf": "http://ports.ubuntu.com/ubuntu-ports",
    "i386":  "http://archive.ubuntu.com/ubuntu",
}

COMPONENTS = ["main", "universe"]

SUPPORTED_ARCHES = list(REPO_ROOTS.keys())

# ---------------------------------------------------------------------------
# Library table
#
# Each entry maps an output zsig name to:
#   (apt_package_name, lib_glob, arch_exclude_list)
#
# lib_glob:
#   None        -- use ALL .a files found in the package (e.g. libc6-dev has
#                  libc.a + libm.a + libpthread.a + ... all merged into one zsig)
#   "glob"      -- fnmatch pattern applied to each .a path inside the extracted
#                  deb; only matching files are included in the zsig
#
# arch_exclude_list:
#   []          -- available on all arches
#   ["i386"]    -- skip for i386 (package not in Ubuntu 22.04 i386 repo)
# ---------------------------------------------------------------------------
LIBS = {
    # ── C runtime / system libraries ──────────────────────────────────────
    "libc6":            ("libc6-dev",            None,                []),
    "libgcc":           ("libgcc-11-dev",        "**/libgcc.a",       []),
    "libstdc++":        ("libstdc++-11-dev",      "**/libstdc++.a",    []),

    # ── TLS / crypto ──────────────────────────────────────────────────────
    "libssl":           ("libssl-dev",           "**/libssl.a",       []),
    "libcrypto-static": ("libssl-dev",           "**/libcrypto.a",    []),
    "libgnutls":        ("libgnutls28-dev",      "**/libgnutls.a",    []),
    # libmbedtls-dev is in universe and not packaged for i386 in jammy
    "libmbedtls":       ("libmbedtls-dev",       None,                ["i386"]),

    # ── Compression ───────────────────────────────────────────────────────
    "zlib":             ("zlib1g-dev",           "**/libz.a",         []),
    "libbz2":           ("libbz2-dev",           "**/libbz2.a",       []),
    "liblzma":          ("liblzma-dev",          "**/liblzma.a",      []),
    "libbrotli":        ("libbrotli-dev",        "**/libbrotli*.a",   []),
    "libzstd":          ("libzstd-dev",          "**/libzstd.a",      []),
    "liblz4":           ("liblz4-dev",           "**/liblz4.a",       []),

    # ── Networking / protocols ────────────────────────────────────────────
    "libcurl":          ("libcurl4-openssl-dev", "**/libcurl.a",      []),
    "libevent":         ("libevent-dev",         "**/libevent.a",     []),

    # ── Data formats / parsing ─────────────────────────────────────────────
    "libprotobuf":      ("libprotobuf-dev",      "**/libprotobuf.a",  []),
    "libxml2":          ("libxml2-dev",          "**/libxml2.a",      []),
    "libpcre2":         ("libpcre2-dev",         "**/libpcre2-8.a",   []),
    "libsqlite3":       ("libsqlite3-dev",       "**/libsqlite3.a",   []),
    "libsnappy":        ("libsnappy-dev",        "**/libsnappy.a",    []),

    # ── Cryptography / security ───────────────────────────────────────────
    "libsodium":        ("libsodium-dev",        "**/libsodium.a",    []),

    # ── Media (universe; all arches) ──────────────────────────────────────
    "libavformat":      ("libavformat-dev",      "**/libavformat.a",  []),
    "libavutil":        ("libavutil-dev",        "**/libavutil.a",    []),
}

# Consistent generation order
LIB_ORDER = list(LIBS.keys())


# ---------------------------------------------------------------------------
# Package index resolution
# ---------------------------------------------------------------------------

def _packages_gz_url(root: str, suite: str, component: str, arch: str) -> str:
    return f"{root}/dists/{suite}/{component}/binary-{arch}/Packages.gz"


def build_package_index(arch: str) -> dict[str, str]:
    """Return {package_name: pool/... filename} for the given arch.

    Checks all suites and components; later entries override earlier ones so
    jammy-security wins over jammy base (latest patched version used).
    """
    root     = REPO_ROOTS[arch]
    combined : dict[str, str] = {}
    cache_dir = CACHE_DIR / "indexes"
    cache_dir.mkdir(parents=True, exist_ok=True)

    for suite in SUITE_PRIORITY:
        for component in COMPONENTS:
            url   = _packages_gz_url(root, suite, component, arch)
            fname = f"Packages.{arch}.{suite}.{component}.gz"
            cached = cache_dir / fname

            if not cached.exists():
                try:
                    urllib.request.urlretrieve(url, cached)
                except Exception:
                    continue  # component may not exist (e.g. universe in ports)

            try:
                with gzip.open(cached, "rt", encoding="utf-8", errors="replace") as f:
                    cur = None
                    for line in f:
                        if line.startswith("Package: "):
                            cur = line[9:].strip()
                        elif line.startswith("Filename: ") and cur:
                            combined[cur] = line[10:].strip()
            except Exception:
                cached.unlink(missing_ok=True)  # corrupt cache — retry next run

    return combined


def resolve_deb_url(arch: str, pkg_name: str, index: dict[str, str]) -> str | None:
    """Return the full download URL for a package, or None if not available."""
    path = index.get(pkg_name)
    if not path:
        return None
    return f"{REPO_ROOTS[arch]}/{path}"


# ---------------------------------------------------------------------------
# Download + extract
# ---------------------------------------------------------------------------

def download_deb(url: str, dest: Path) -> bool:
    """Download a .deb to dest. Return True on success."""
    if dest.exists():
        return True
    print(f"    Downloading {dest.name} ...")
    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as exc:
        print(f"    ERROR downloading {dest.name}: {exc}", file=sys.stderr)
        dest.unlink(missing_ok=True)
        return False


def extract_deb_libs(deb_path: Path, extract_dir: Path) -> list[Path]:
    """Extract all .a files from a .deb into extract_dir. Return list of paths."""
    result = subprocess.run(
        ["dpkg-deb", "--fsys-tarfile", str(deb_path)],
        capture_output=True,
    )
    if result.returncode != 0:
        return []
    subprocess.run(
        ["tar", "-C", str(extract_dir), "--wildcards", "--wildcards-match-slash",
         "-x", "*.a"],
        input=result.stdout, capture_output=True,
    )
    return sorted(extract_dir.rglob("*.a"))


def filter_libs(all_libs: list[Path], glob_pat: str | None) -> list[Path]:
    """Filter extracted .a paths by glob pattern (or return all if None)."""
    if glob_pat is None:
        return all_libs
    matched = []
    for lib in all_libs:
        # Match against the full relative path string
        if fnmatch.fnmatch(lib.name, glob_pat.lstrip("**/")) \
                or fnmatch.fnmatch(str(lib), glob_pat):
            matched.append(lib)
    return matched


# ---------------------------------------------------------------------------
# zsig generation (delegates to zsig_utils)
# ---------------------------------------------------------------------------

def generate_zsig_from_libs(lib_paths: list[Path], out_zsig: Path,
                             prefix: str) -> tuple[bool, int]:
    """Generate and merge zsigs for a list of .a files. Returns (ok, sig_count)."""
    # Use zsig_utils directly -- generate_zsig_from_lib() returns (bool, int)
    # process_lib() in generate-zsig.py returns bare bool (not suitable here).
    from zsig_utils import generate_zsig_from_lib, merge_zsigs
    out_zsig.parent.mkdir(parents=True, exist_ok=True)

    if len(lib_paths) == 1:
        return generate_zsig_from_lib(str(lib_paths[0]), str(out_zsig), prefix=prefix,
                                      log=print)

    with tempfile.TemporaryDirectory() as tmp:
        parts = []
        total = 0
        for lib in lib_paths:
            part = Path(tmp) / f"{lib.stem}.zsig"
            ok, n = generate_zsig_from_lib(str(lib), str(part), prefix=prefix, log=print)
            if ok:
                parts.append(str(part))
                total += n
        if not parts:
            return False, 0
        ok, final_n = merge_zsigs(parts, str(out_zsig))
        return ok, (final_n or total)


# ---------------------------------------------------------------------------
# Per-library entry point
# ---------------------------------------------------------------------------

def generate_one(zsig_name: str, arch: str, index: dict[str, str],
                 outdir: Path, cache_dir: Path, force: bool) -> bool:
    """Generate one zsig. Returns True on success (or skip)."""
    pkg_name, lib_glob, arch_exclude = LIBS[zsig_name]

    if arch in arch_exclude:
        print(f"  {zsig_name}: skipped (not available for {arch})")
        return True

    out_zsig = outdir / arch / f"{zsig_name}.zsig"
    if out_zsig.exists() and not force:
        print(f"  {zsig_name}: already exists ({out_zsig.stat().st_size:,} bytes) — skipping")
        return True

    url = resolve_deb_url(arch, pkg_name, index)
    if not url:
        print(f"  {zsig_name}: {pkg_name} not found in Ubuntu index for {arch}")
        return False

    deb_file = cache_dir / Path(url).name
    if not download_deb(url, deb_file):
        return False

    with tempfile.TemporaryDirectory() as tmp:
        extract_dir = Path(tmp) / "extracted"
        extract_dir.mkdir()
        all_libs = extract_deb_libs(deb_file, extract_dir)

        if not all_libs:
            print(f"  {zsig_name}: no .a files found in {pkg_name}", file=sys.stderr)
            return False

        selected = filter_libs(all_libs, lib_glob)
        if not selected:
            print(f"  {zsig_name}: glob {lib_glob!r} matched nothing in {pkg_name}",
                  file=sys.stderr)
            print(f"    Available: {[p.name for p in all_libs[:10]]}", file=sys.stderr)
            return False

        prefix = zsig_name.lstrip("lib").replace("-", "_").replace("+", "x")
        ok, n = generate_zsig_from_libs(selected, out_zsig, prefix)

    if ok:
        size = out_zsig.stat().st_size
        print(f"  {zsig_name}: {n} sigs  ({size:,} bytes)  -> {out_zsig}")
    else:
        print(f"  {zsig_name}: zsig generation failed", file=sys.stderr)
    return ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def list_libs():
    print("Library zsig targets (package -> output zsig):")
    print(f"  {'zsig name':<25} {'apt package':<30} {'lib glob':<30} {'excluded arches'}")
    print("  " + "-" * 95)
    for name in LIB_ORDER:
        pkg, glob, excl = LIBS[name]
        print(f"  {name:<25} {pkg:<30} {str(glob):<30} {excl or 'all arches'}")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--arch",      choices=SUPPORTED_ARCHES,
                    help="Target architecture")
    ap.add_argument("--all-arches", action="store_true",
                    help="Generate for all supported arches (amd64, arm64, armhf, i386)")
    ap.add_argument("--lib",       nargs="+", choices=LIB_ORDER,
                    help="Specific library zsig(s) to generate (default: all)")
    ap.add_argument("--output-dir",
                    help=f"Override output directory (default: {ZSIG_OUT_DIR})")
    ap.add_argument("--force",     action="store_true",
                    help="Regenerate even if output zsig already exists")
    ap.add_argument("--no-cache",  action="store_true",
                    help="Delete cached Packages index files and re-download")
    ap.add_argument("--list",      action="store_true",
                    help="List available library targets and exit")
    args = ap.parse_args()

    if args.list:
        list_libs()
        return

    if not args.arch and not args.all_arches:
        ap.error("specify --arch ARCH or --all-arches")

    arches     = SUPPORTED_ARCHES if args.all_arches else [args.arch]
    libs_todo  = args.lib or LIB_ORDER
    outdir     = Path(args.output_dir) if args.output_dir else ZSIG_OUT_DIR
    cache_dir  = CACHE_DIR / "debs"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if args.no_cache:
        idx_cache = CACHE_DIR / "indexes"
        if idx_cache.exists():
            shutil.rmtree(idx_cache)
        print("Package index cache cleared.")

    total = ok = 0
    for arch in arches:
        print(f"\n=== {arch} — resolving package index ===")
        index = build_package_index(arch)
        print(f"    index: {len(index)} packages")

        for lib in libs_todo:
            total += 1
            try:
                if generate_one(lib, arch, index, outdir, cache_dir, args.force):
                    ok += 1
            except Exception as exc:
                import traceback
                print(f"  {lib}: EXCEPTION: {exc}", file=sys.stderr)
                traceback.print_exc()

    print(f"\n{'='*50}")
    print(f"Done: {ok}/{total} succeeded")
    if ok < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
