#!/usr/bin/env python3
"""
Generate r2 zignatures from Debian/Ubuntu library packages.

Downloads .deb packages for a given architecture, extracts static libraries,
and generates zsig files. Covers the most commonly requested libraries in
the IDA FLIRT / RE community:
  libstdc++, libcrypto, libprotobuf, libsodium, libsqlite3, libxml2,
  libpcre2, libzstd, liblz4, libsnappy

Requirements:
    - Python 3.8+, r2pipe, wget, ar, dpkg-deb

Usage:
    generate-debian-libs-zsig.py --arch amd64
    generate-debian-libs-zsig.py --arch arm64
    generate-debian-libs-zsig.py --all-arches
    generate-debian-libs-zsig.py --list

Ubuntu 22.04 (jammy) package versions are auto-detected.
"""
import argparse, os, shutil, subprocess, sys, tempfile, urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR",
                   Path.home() / ".local" / "share" / "radare2"))
ZSIG_OUT_DIR = R2_DATA_DIR / "zigns" / "debian"

UBUNTU_POOLS = {
    "amd64": "http://archive.ubuntu.com/ubuntu/pool/main",
    "arm64": "http://ports.ubuntu.com/ubuntu-ports/pool/main",
    "armhf": "http://ports.ubuntu.com/ubuntu-ports/pool/main",
    "i386":  "http://archive.ubuntu.com/ubuntu/pool/main",
}

# Library definitions: {lib_name: (source_pkg, deb_name_pattern, lib_file)}
# Uses Ubuntu 22.04 (jammy) versions
LIBS = {
    "libstdc++": {
        "amd64": ("/usr/lib/gcc/x86_64-linux-gnu/11/libstdc++.a",
                  "g/gcc-11/libstdc++-11-dev_11.4.0-1ubuntu1~22.04.3_amd64.deb"),
        "arm64": ("extracted/usr/lib/gcc/aarch64-linux-gnu/11/libstdc++.a",
                  "g/gcc-11/libstdc++-11-dev_11.4.0-1ubuntu1~22.04.3_arm64.deb"),
    },
    "libprotobuf": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/libprotobuf.a",
                  "p/protobuf/libprotobuf-dev_3.12.4-1ubuntu7.22.04.6_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/libprotobuf.a",
                  "p/protobuf/libprotobuf-dev_3.12.4-1ubuntu7.22.04.6_arm64.deb"),
    },
    "libsodium": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/libsodium.a",
                  "libs/libsodium/libsodium-dev_1.0.18-1ubuntu0.22.04.1_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/libsodium.a",
                  "libs/libsodium/libsodium-dev_1.0.18-1ubuntu0.22.04.1_arm64.deb"),
    },
    "libsqlite3": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/libsqlite3.a",
                  "s/sqlite3/libsqlite3-dev_3.37.2-2ubuntu0.7_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/libsqlite3.a",
                  "s/sqlite3/libsqlite3-dev_3.37.2-2ubuntu0.7_arm64.deb"),
    },
    "libxml2": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/libxml2.a",
                  "libx/libxml2/libxml2-dev_2.9.13+dfsg-1ubuntu0.12_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/libxml2.a",
                  "libx/libxml2/libxml2-dev_2.9.13+dfsg-1ubuntu0.12_arm64.deb"),
    },
    "libpcre2": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/libpcre2-8.a",
                  "p/pcre2/libpcre2-dev_10.39-3ubuntu0.1_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/libpcre2-8.a",
                  "p/pcre2/libpcre2-dev_10.39-3ubuntu0.1_arm64.deb"),
    },
    "libzstd": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/libzstd.a",
                  "libz/libzstd/libzstd-dev_1.4.8+dfsg-3build1_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/libzstd.a",
                  "libz/libzstd/libzstd-dev_1.4.8+dfsg-3build1_arm64.deb"),
    },
    "liblz4": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/liblz4.a",
                  "l/lz4/liblz4-dev_1.9.3-2build2_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/liblz4.a",
                  "l/lz4/liblz4-dev_1.9.3-2build2_arm64.deb"),
    },
    "libsnappy": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/libsnappy.a",
                  "s/snappy/libsnappy-dev_1.1.8-1build3_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/libsnappy.a",
                  "s/snappy/libsnappy-dev_1.1.8-1build3_arm64.deb"),
    },
    "libcrypto-static": {
        "amd64": ("/usr/lib/x86_64-linux-gnu/libcrypto.a",
                  "o/openssl/libssl-dev_3.0.2-0ubuntu1.26_amd64.deb"),
        "arm64": ("extracted/usr/lib/aarch64-linux-gnu/libcrypto.a",
                  "o/openssl/libssl-dev_3.0.2-0ubuntu1.26_arm64.deb"),
    },
}

SUPPORTED_ARCHES = list(UBUNTU_POOLS.keys())


def download_and_extract(arch: str, deb_path: str, extract_dir: Path,
                          cache_dir: Path) -> bool:
    """Download a .deb and extract .a files into extract_dir."""
    deb_name = Path(deb_path).name
    cached_deb = cache_dir / deb_name

    if not cached_deb.exists():
        pool = UBUNTU_POOLS[arch]
        url = f"{pool}/{deb_path}"
        print(f"    Downloading {deb_name}...")
        try:
            urllib.request.urlretrieve(url, cached_deb)
        except Exception as exc:
            print(f"    ERROR: {exc}", file=sys.stderr)
            return False

    # Extract .a files
    result = subprocess.run(
        ["dpkg-deb", "--fsys-tarfile", str(cached_deb)],
        capture_output=True
    )
    if result.returncode != 0:
        return False

    subprocess.run(
        ["tar", "-C", str(extract_dir), "--wildcards", "--wildcards-match-slash",
         "-x", "*.a"],
        input=result.stdout, capture_output=True
    )
    return True


def generate_lib_zsig(lib_name: str, arch: str, output_dir: Path,
                       work_dir: Path, cache_dir: Path) -> bool:
    """Generate zsig for one library on one architecture."""
    if arch not in LIBS.get(lib_name, {}):
        print(f"  No recipe for {lib_name}/{arch}")
        return False

    lib_path_str, deb_path = LIBS[lib_name][arch]

    # Check if lib is already installed (amd64 on amd64 host)
    lib_path = Path(lib_path_str)
    if not lib_path.is_absolute():
        # Relative = needs extraction from deb
        extract_dir = work_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        if not download_and_extract(arch, deb_path, extract_dir, cache_dir):
            return False
        lib_path = work_dir / lib_path_str
    
    if not lib_path.exists():
        # Try downloading even for amd64
        extract_dir = work_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        if not download_and_extract(arch, deb_path, extract_dir, cache_dir):
            print(f"  Library not found: {lib_path}", file=sys.stderr)
            return False
        deb_name = Path(deb_path).name.replace(f"_{arch}.deb", "").replace("-dev", "")
        # Find extracted .a
        candidates = list((work_dir / "extracted").rglob(f"lib{lib_name.lstrip('lib')}*.a"))
        if not candidates:
            print(f"  Could not find .a after extraction", file=sys.stderr)
            return False
        lib_path = candidates[0]

    out_zsig = output_dir / arch / f"{lib_name}.zsig"
    out_zsig.parent.mkdir(parents=True, exist_ok=True)

    # Import generate-zsig tool
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen", SCRIPT_DIR / "generate-zsig.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    success, count = gen.generate_zsig_from_lib(str(lib_path), str(out_zsig),
                                                  prefix=lib_name.lstrip("lib"), log=print)
    if success:
        print(f"  --> {out_zsig.name}: {count} sigs")
    return success


def list_libs():
    print("Available library zsig targets:")
    for name, arches in sorted(LIBS.items()):
        available = ", ".join(sorted(arches.keys()))
        print(f"  {name:<25} ({available})")


def main():
    ap = argparse.ArgumentParser(description="Generate r2 zsigs for popular Debian/Ubuntu libraries")
    ap.add_argument("--list", action="store_true", help="List available libraries")
    ap.add_argument("--arch", choices=SUPPORTED_ARCHES, help="Target architecture")
    ap.add_argument("--all-arches", action="store_true", help="Generate for amd64 + arm64")
    ap.add_argument("--lib", nargs="+", choices=list(LIBS.keys()),
                    help="Specific libraries (default: all)")
    ap.add_argument("--output-dir", help=f"Override output dir (default: {ZSIG_OUT_DIR})")
    args = ap.parse_args()

    if args.list:
        list_libs()
        return

    arches = (["amd64", "arm64"] if args.all_arches
              else [args.arch] if args.arch else ["amd64"])
    libs_to_gen = args.lib or list(LIBS.keys())
    outdir = Path(args.output_dir) if args.output_dir else ZSIG_OUT_DIR

    cache_dir = R2_DATA_DIR / "cache" / "debian-libs"
    cache_dir.mkdir(parents=True, exist_ok=True)

    total = ok = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        for arch in arches:
            print(f"\n=== {arch} ===")
            for lib in libs_to_gen:
                print(f"  {lib} ...")
                total += 1
                try:
                    if generate_lib_zsig(lib, arch, outdir, Path(tmpdir), cache_dir):
                        ok += 1
                except Exception as exc:
                    print(f"  ERROR: {exc}", file=sys.stderr)

    print(f"\nDone: {ok}/{total}")


if __name__ == "__main__":
    main()
