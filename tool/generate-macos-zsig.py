#!/usr/bin/env python3
"""
Generate r2 zignatures from Apple open source for macOS analysis.

Produces native macOS libSystem and libm signatures by:
  1. Downloading the macOS SDK tarball (joseluisq/macosx-sdks) for headers/sysroot
  2. Downloading Apple open source Libc + Libm from apple-oss-distributions
  3. Cross-compiling with clang --target=<arch>-apple-macos using the SDK as sysroot
  4. Generating zsig files from the compiled Mach-O objects

No Apple hardware required.  clang on Linux already supports Apple targets and
produces genuine Mach-O objects when given a macOS sysroot.

Coverage:
  macos/arm64/libSystem.zsig  — Apple Silicon (M1/M2/M3) libSystem C runtime
  macos/arm64/libm.zsig       — Apple Silicon math library
  macos/x86_64/libSystem.zsig — Intel macOS libSystem C runtime
  macos/x86_64/libm.zsig      — Intel macOS math library

Key functions named in output (libSystem):
  malloc, free, realloc, calloc, memcpy, memmove, memset, memcmp,
  strlen, strcpy, strncpy, strcmp, strncmp, strcat, strchr, strstr,
  printf, sprintf, snprintf, fprintf, fopen, fread, fwrite, fclose,
  qsort, bsearch, strtol, strtod, atoi, atof, getenv, exit, abort, ...

Key functions named in output (libm):
  sin, cos, tan, asin, acos, atan, atan2, sqrt, pow, exp, log,
  ceil, floor, round, fabs, fmod, sinh, cosh, tanh, ...

Requirements:
  clang >= 10 with Apple target support (standard apt install clang)
  ar, tar, xz (standard system utilities)
  r2pipe (pip install r2pipe)

Usage:
  generate-macos-zsig.py                        # all arches, all libs
  generate-macos-zsig.py --arch arm64           # Apple Silicon only
  generate-macos-zsig.py --arch x86_64          # Intel only
  generate-macos-zsig.py --lib libm             # single library
  generate-macos-zsig.py --sdk-version 15.4     # explicit SDK version
  generate-macos-zsig.py --force                # regenerate existing
  generate-macos-zsig.py --no-cache             # re-download everything

Output:
  zigns/macos/arm64/libSystem.zsig
  zigns/macos/arm64/libm.zsig
  zigns/macos/x86_64/libSystem.zsig
  zigns/macos/x86_64/libm.zsig

After generation, update macos-arm64.r2 and macos-x64.r2 to load these
native zsigs in addition to the debian/ fallback set.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR   = Path(__file__).parent
R2_DATA_DIR  = Path(os.environ.get("R2_DATA_DIR",
                    Path.home() / ".local" / "share" / "radare2"))
ZSIG_OUT_DIR = R2_DATA_DIR / "zigns" / "macos"
CACHE_DIR    = R2_DATA_DIR / "cache" / "macos-sdk"

# ---------------------------------------------------------------------------
# SDK configuration
# ---------------------------------------------------------------------------
SDK_DEFAULT_VERSION = "15.4"
SDK_URL_TEMPLATE = (
    "https://github.com/joseluisq/macosx-sdks/releases/download"
    "/{version}/MacOSX{version}.sdk.tar.xz"
)

# ---------------------------------------------------------------------------
# Apple open source package versions
# (github.com/apple-oss-distributions)
# ---------------------------------------------------------------------------
LIBC_TAG  = "Libc-1752.120.2"
LIBM_TAG  = "Libm-2026"

# ---------------------------------------------------------------------------
# Arch → clang target mapping
# ---------------------------------------------------------------------------
ARCHES = {
    "arm64": {
        "clang_target": "arm64-apple-macos12",
        "clang_flags":  ["-arch", "arm64"],
        "sdk_min":      "12.0",
        "desc":         "Apple Silicon (AArch64, M1/M2/M3)",
    },
    "x86_64": {
        "clang_target": "x86_64-apple-macos10.14",
        "clang_flags":  ["-arch", "x86_64"],
        "sdk_min":      "10.14",
        "desc":         "Intel macOS (x86-64)",
    },
}

# ---------------------------------------------------------------------------
# Library definitions
# ---------------------------------------------------------------------------
# Each entry:
#   org:       GitHub org/repo under apple-oss-distributions
#   tag:       Git tag to download
#   src_dirs:  Subdirectories to recurse for .c / .s source files
#   prefix:    Zsig name prefix
#   skip_dirs: Path fragments to skip (test code, arch-specific wrong arch)
# ---------------------------------------------------------------------------
LIBS = {
    "libSystem": {
        "org":       "apple-oss-distributions/Libc",
        "tag":       LIBC_TAG,
        "src_dirs":  [
            "string",                   # memcpy, memmove, strlen, strcpy, ...
            "string/FreeBSD",           # portable C fallbacks
            "string/NetBSD",
            "stdlib",                   # malloc, qsort, strtol, atoi, ...
            "stdlib/FreeBSD",
            "stdlib/NetBSD",
            "stdlib/OpenBSD",
            "gen",                      # clock_gettime, confstr, errlst, ...
            "gen/FreeBSD",
            "gen/NetBSD",
            "stdio",                    # printf, fopen, fread, ...
            "gdtoa",                    # strtod, dtoa (number parsing/formatting)
            "locale",                   # setlocale, localeconv, ...
            "regex",                    # regcomp, regexec, ...
            "util",                     # misc utility functions
            "net",                      # inet_aton, getifaddrs, ...
            "fbsdcompat",               # FreeBSD compat shims
            "nbsdcompat",               # NetBSD compat shims
            "os",                       # os_log stubs
        ],
        # Skip: test code, manpages, xcodeproj scaffolding, i386-only code,
        #       exclave (secure enclave), emulated (Rosetta), uuid (complex deps)
        "skip_dirs": [
            "tests", "test", "man", "xcodeproj", "xcodescripts",
            "i386", "exclave", "emulated", "uuid", "gmon",
            "posix1e", "db", "collections",
            "compat-43",   # very old BSD compat -- not worth the noise
        ],
        "prefix":    "macos_libc",
        "desc":      "macOS C runtime (libSystem.B.dylib)",
    },
    "libm": {
        "org":       "apple-oss-distributions/Libm",
        "tag":       LIBM_TAG,
        "src_dirs":  ["Source"],
        "skip_dirs": ["PowerPC", "man3", "Exports", "xcodeproj"],
        "prefix":    "macos_libm",
        "desc":      "macOS math library (libm.dylib / part of libSystem)",
    },
}

LIB_ORDER = list(LIBS.keys())


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, **kwargs)


def log(msg: str) -> None:
    print(msg, flush=True)


def check_clang(arch: str) -> bool:
    """Verify clang supports the given Apple target."""
    cfg = ARCHES[arch]
    r = run(["clang", "--version"])
    if r.returncode != 0:
        log("ERROR: clang not found. Install with: apt install clang")
        return False

    # Quick compile smoke-test
    test_c = "int _test_fn(int x) { return x + 1; }"
    test = run(
        ["clang", f"--target={cfg['clang_target']}",
         "-x", "c", "-", "-c", "-o", "/dev/null",
         "-w"],          # suppress warnings during check
        input=test_c.encode(),
    )
    if test.returncode != 0:
        err = test.stderr.decode(errors="replace")
        log(f"ERROR: clang cannot target {cfg['clang_target']}:\n{err[:300]}")
        return False

    ver = r.stdout.decode().splitlines()[0].strip()
    log(f"  clang: {ver}  target={cfg['clang_target']} ✓")
    return True


# ---------------------------------------------------------------------------
# SDK download + extraction
# ---------------------------------------------------------------------------

def download_sdk(version: str, cache_dir: Path) -> Path | None:
    """Download and cache the macOS SDK tarball. Return path to SDK root dir."""
    sdk_name  = f"MacOSX{version}.sdk"
    sdk_dir   = cache_dir / sdk_name
    tarball   = cache_dir / f"{sdk_name}.tar.xz"

    if sdk_dir.exists() and (sdk_dir / "usr" / "include").exists():
        log(f"  SDK {version}: cached at {sdk_dir}")
        return sdk_dir

    if not tarball.exists():
        url = SDK_URL_TEMPLATE.format(version=version)
        log(f"  Downloading macOS SDK {version} from {url}")
        log(f"  (this is ~100-300 MB; cached after first download)")
        try:
            urllib.request.urlretrieve(url, tarball,
                reporthook=_download_progress)
            print()  # newline after progress
        except Exception as exc:
            log(f"  ERROR downloading SDK: {exc}")
            tarball.unlink(missing_ok=True)
            return None

    log(f"  Extracting {tarball.name} ...")
    cache_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = run(["tar", "-xJf", str(tarball), "-C", str(cache_dir)])
        if result.returncode != 0:
            log(f"  ERROR extracting SDK: {result.stderr.decode()[:200]}")
            return None
    except Exception as exc:
        log(f"  ERROR extracting SDK: {exc}")
        return None

    # SDK tarballs may extract as MacOSX{version}.sdk/ directly, or with a
    # wrapper dir.  Find it.
    candidates = sorted(cache_dir.glob("MacOSX*.sdk"))
    if not candidates:
        # Some tarballs wrap in a platform dir
        candidates = sorted(cache_dir.rglob("MacOSX*.sdk"))
    if not candidates:
        log("  ERROR: could not find SDK directory after extraction")
        return None

    sdk_path = candidates[0]
    log(f"  SDK root: {sdk_path}")
    return sdk_path


def _download_progress(count, block_size, total_size):
    if total_size > 0:
        pct = min(int(count * block_size * 100 / total_size), 100)
        mb  = count * block_size / 1_048_576
        print(f"\r    {mb:6.1f} MB  {pct:3d}%", end="", flush=True)


# ---------------------------------------------------------------------------
# Apple open source download
# ---------------------------------------------------------------------------

def download_apple_oss(org_repo: str, tag: str, cache_dir: Path) -> Path | None:
    """Download and cache an apple-oss-distributions tarball.

    Returns the path to the extracted source root directory.
    """
    repo_name  = org_repo.split("/")[1]
    tarball    = cache_dir / f"{tag}.tar.gz"
    # GitHub extracts as <repo>-<tag>/
    extract_to = cache_dir / f"{repo_name}-{tag}"

    if extract_to.exists():
        log(f"  {repo_name} {tag}: cached at {extract_to}")
        return extract_to

    if not tarball.exists():
        url = (f"https://github.com/{org_repo}/archive/refs/tags/{tag}.tar.gz")
        log(f"  Downloading {repo_name} {tag} ...")
        cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            urllib.request.urlretrieve(url, tarball,
                reporthook=_download_progress)
            print()
        except Exception as exc:
            log(f"  ERROR downloading {repo_name}: {exc}")
            tarball.unlink(missing_ok=True)
            return None

    log(f"  Extracting {tarball.name} ...")
    cache_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(cache_dir)
    except Exception as exc:
        log(f"  ERROR extracting {repo_name}: {exc}")
        return None

    # GitHub archives extract as <Repo>-<tag>/ where tag may already start
    # with the repo name, giving a doubled prefix: Libm-Libm-2026/
    # Find the extracted directory by looking for any dir matching Repo-*,
    # filtering out files (tarballs etc.).
    candidates = [
        p for p in cache_dir.glob(f"{repo_name}-*") if p.is_dir()
    ]
    if not candidates:
        log(f"  ERROR: could not find extracted directory for {repo_name}")
        return None

    # If extract_to already exists among candidates just use it; otherwise
    # pick the freshest directory and rename it to the canonical path.
    if extract_to in candidates:
        src_root = extract_to
    else:
        src_root = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0]
        if src_root != extract_to:
            src_root.rename(extract_to)

    log(f"  Source root: {extract_to}")
    return extract_to


# ---------------------------------------------------------------------------
# Source collection
# ---------------------------------------------------------------------------

def collect_sources(src_root: Path, src_dirs: list[str],
                    skip_dirs: list[str], arch: str) -> list[Path]:
    """Collect compilable .c and .s source files, recursing into src_dirs."""
    skip_set = {s.lower() for s in skip_dirs}

    # For x86_64: also skip ARM-specific dirs; for arm64: skip Intel/x86 dirs
    if arch == "arm64":
        skip_set.update({"intel", "x86_64", "i386", "i686", "ppc", "powerpc"})
    else:
        skip_set.update({"arm", "arm64", "aarch64"})

    sources = []
    for rel_dir in src_dirs:
        d = src_root / rel_dir
        if not d.exists():
            continue
        for ext in ("*.c", "*.s", "*.S"):
            for f in d.rglob(ext):          # recursive — descends into subdirs
                # Skip if any path component matches the skip set
                parts = {p.lower() for p in f.relative_to(src_root).parts}
                if parts & skip_set:
                    continue
                sources.append(f)

    return sorted(set(sources))   # deduplicate (rglob across overlapping dirs)


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def compile_sources(
    sources: list[Path],
    src_root: Path,
    sdk_path: Path,
    arch: str,
    work_dir: Path,
) -> list[Path]:
    """Cross-compile source files to Mach-O objects. Returns list of .o paths."""
    cfg       = ARCHES[arch]
    target    = cfg["clang_target"]
    sysroot   = str(sdk_path)
    obj_dir   = work_dir / "objects"
    obj_dir.mkdir(exist_ok=True)

    # Clang freestanding includes for missing macros
    clang_builtins = Path(
        run(["clang", "--print-resource-dir"]).stdout.decode().strip()
    ) / "include"

    base_flags = [
        f"--target={target}",
        "-isysroot", sysroot,
        f"-mmacosx-version-min={cfg['sdk_min']}",
        "-I", str(clang_builtins),
        # Optimise for function signature fidelity
        "-O2",
        "-ffunction-sections",
        "-fdata-sections",
        # Suppress warnings that would clutter output (not errors)
        "-w",
        # Don't link; object files only
        "-c",
    ]

    obj_files = []
    n_ok = n_fail = 0

    for src in sources:
        # Derive a unique object file name from the path relative to src_root
        rel = src.relative_to(src_root)
        obj_name = str(rel).replace("/", "_").replace(".c", ".o").replace(".s", ".o").replace(".S", ".o")
        obj = obj_dir / obj_name

        cmd = ["clang"] + base_flags + [str(src), "-o", str(obj)]
        r = run(cmd, timeout=30)

        if r.returncode == 0 and obj.exists() and obj.stat().st_size > 0:
            obj_files.append(obj)
            n_ok += 1
        else:
            n_fail += 1
            if n_fail <= 5:   # show first few failures for diagnostics
                err = r.stderr.decode(errors="replace").strip()
                log(f"    skip {src.name}: {err.splitlines()[0][:100] if err else 'empty output'}")
            elif n_fail == 6:
                log(f"    (further compile failures suppressed)")

    log(f"    compiled {n_ok}/{n_ok+n_fail} sources"
        + (f"  ({n_fail} skipped)" if n_fail else ""))
    return obj_files


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Symbol resolution and function byte extraction
# ---------------------------------------------------------------------------

def _llvm_nm_available() -> bool:
    return shutil.which("llvm-nm") is not None


def get_function_layout(obj_path: Path) -> list[tuple[str, int, int, int]]:
    """Return [(clean_name, file_offset, func_size, min_size_ok)] for all
    exported text functions in a Mach-O MH_OBJECT file.

    Strategy:
      - llvm-nm --format=posix gives: name, type(T), section_relative_offset
      - rabin2 -S gives: __text section paddr (= file offset) and size
      - Function sizes are computed from consecutive offsets within the section

    We do NOT open the full Mach-O in r2 for analysis, because r2 maps
    MH_OBJECT __text sections to vaddr=0x0 and refuses to analyze code there.
    Instead the caller extracts raw bytes per function and opens them as flat
    ARM64/x86-64 binaries.
    """
    result = run(["llvm-nm", "--format=posix", str(obj_path)])
    if result.returncode != 0:
        return []

    # Parse: "name T offset size"
    raw: list[tuple[str, int]] = []          # (clean_name, section_relative_offset)
    for line in result.stdout.decode(errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        stype = parts[1]
        if stype != "T":                      # only exported global text symbols
            continue
        try:
            offset = int(parts[2], 16)
        except ValueError:
            continue
        name  = parts[0]
        clean = name.lstrip("_") if name.startswith("_") else name
        raw.append((clean, offset))

    if not raw:
        return []

    # Sort by section-relative offset so we can compute sizes from gaps
    raw.sort(key=lambda x: x[1])

    # Get __text section: file offset (paddr) and total size
    rb = run(["rabin2", "-S", str(obj_path)])
    text_paddr: int | None = None
    text_size:  int        = 0
    for line in rb.stdout.decode(errors="replace").splitlines():
        if "__text" not in line:
            continue
        parts = line.split()
        # rabin2 -S columns: nth paddr size vaddr vsize perm flags type name
        if len(parts) >= 3:
            try:
                text_paddr = int(parts[1], 16)
                text_size  = int(parts[2], 16)
                break
            except ValueError:
                pass

    if text_paddr is None or text_size == 0:
        return []

    # Build result: compute each function's size from the gap to the next symbol
    layout: list[tuple[str, int, int, int]] = []
    for i, (name, sect_offset) in enumerate(raw):
        if i + 1 < len(raw):
            func_size = raw[i + 1][1] - sect_offset
        else:
            func_size = text_size - sect_offset

        if func_size <= 0:
            continue

        file_offset = text_paddr + sect_offset
        layout.append((name, file_offset, func_size, func_size))

    return layout


# ---------------------------------------------------------------------------
# zsig generation  (flat-binary approach — avoids Mach-O vaddr=0 issue)
# ---------------------------------------------------------------------------

def generate_zsig(obj_files: list[Path], out_zsig: Path,
                  prefix: str, r2_arch: str = "arm",
                  r2_bits: int = 64) -> int:
    """Generate merged zsig from Mach-O object files.  Returns sig count.

    Core approach: instead of opening the full Mach-O in r2 (which cannot
    analyze code at vaddr=0 — the default mapping for MH_OBJECT __text
    sections), we extract each exported function's raw bytes and open them
    as a flat ARM64/x86-64 binary.  This gives r2 a clean address space
    to analyze and produces 100%% named zsig entries.
    """
    if not obj_files:
        return 0

    out_zsig.parent.mkdir(parents=True, exist_ok=True)
    nm_ok = _llvm_nm_available()
    if not nm_ok:
        log("  WARNING: llvm-nm not found — cannot extract function layout (install llvm)")
        return 0

    part_zsigs: list[str] = []
    n_funcs = n_ok = 0

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        obj_bytes_cache: dict[Path, bytes] = {}

        for obj in obj_files:
            layout = get_function_layout(obj)
            if not layout:
                continue

            # Cache object bytes once per file
            if obj not in obj_bytes_cache:
                obj_bytes_cache[obj] = obj.read_bytes()
            obj_data = obj_bytes_cache[obj]

            for func_name, file_offset, func_size, _ in layout:
                n_funcs += 1
                if func_size < 4:          # below zign.minsz threshold
                    continue
                end = file_offset + func_size
                if end > len(obj_data):
                    continue

                func_bytes = obj_data[file_offset:end]
                raw_bin    = tmp_path / f"{func_name}.bin"
                raw_bin.write_bytes(func_bytes)

                part = tmp_path / f"{func_name}.zsig"
                r2_script = (
                    f"e asm.arch={r2_arch}; "
                    f"e asm.bits={r2_bits}; "
                    f"e anal.followcall=0; "
                    f"e zign.mincc=1; "
                    f"e zign.minsz=4; "
                    f"af @ 0; afn {func_name}; zg; zos {part}"
                )
                result = run(
                    ["r2", "-q", "-c", r2_script, str(raw_bin)],
                    timeout=30,
                )
                if result.returncode == 0 and part.exists() and part.stat().st_size > 0:
                    part_zsigs.append(str(part))
                    n_ok += 1

        if not part_zsigs:
            log("    ERROR: no zsig parts generated")
            return 0

        log(f"    {n_ok}/{n_funcs} functions → zsig entries")

        # Merge all per-function part zsigs
        import r2pipe
        r2 = r2pipe.open("malloc://1", flags=["-e", "scr.color=0", "-2"])
        for p in part_zsigs:
            r2.cmd(f"zo {p}")
        r2.cmd(f"zos {out_zsig}")
        r2.quit()

    if not out_zsig.exists():
        return 0

    # Count entries via r2 (binary zsig format; strings-based count is unreliable)
    import r2pipe
    r2 = r2pipe.open("malloc://1", flags=["-e", "scr.color=0", "-2"])
    r2.cmd(f"zo {out_zsig}")
    try:
        count = int(r2.cmd("z~?").strip())
    except (ValueError, AttributeError):
        count = n_ok
    r2.quit()
    return count


# ---------------------------------------------------------------------------
# Per-library entry point
# ---------------------------------------------------------------------------

def generate_one(lib_name: str, arch: str, sdk_path: Path,
                 force: bool) -> bool:
    """Generate zsig for one library + arch. Returns True on success."""
    cfg      = LIBS[lib_name]
    out_zsig = ZSIG_OUT_DIR / arch / f"{lib_name}.zsig"

    if out_zsig.exists() and not force:
        log(f"  {lib_name}/{arch}: already exists"
            f" ({out_zsig.stat().st_size:,} bytes) — skipping")
        return True

    log(f"\n  [{arch}] {lib_name}: {cfg['desc']}")

    # Download source
    src_root = download_apple_oss(cfg["org"], cfg["tag"], CACHE_DIR / "src")
    if not src_root:
        return False

    # Collect compilable sources
    sources = collect_sources(src_root, cfg["src_dirs"], cfg["skip_dirs"], arch)
    log(f"    found {len(sources)} source files")
    if not sources:
        log(f"    ERROR: no source files found in {cfg['src_dirs']}")
        return False

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        # Compile
        obj_files = compile_sources(sources, src_root, sdk_path, arch, work)
        if not obj_files:
            log(f"    ERROR: nothing compiled for {lib_name}/{arch}")
            return False

        # Generate zsig
        r2_arch = "arm" if arch == "arm64" else "x86"
        r2_bits = 64
        count = generate_zsig(obj_files, out_zsig, prefix=cfg["prefix"],
                              r2_arch=r2_arch, r2_bits=r2_bits)

    if count > 0:
        size = out_zsig.stat().st_size
        log(f"    -> {out_zsig.relative_to(R2_DATA_DIR)}: "
            f"{count} sigs  ({size:,} bytes)")
        return True
    else:
        log(f"    ERROR: zsig generation failed (0 signatures)")
        out_zsig.unlink(missing_ok=True)
        return False


# ---------------------------------------------------------------------------
# Profile updater
# ---------------------------------------------------------------------------

def update_profiles(generated: dict[tuple[str, str], bool]) -> None:
    """Add native macos/ zo lines to macos-arm64.r2 and macos-x64.r2
    if the corresponding zsig was generated successfully."""
    profiles_dir = R2_DATA_DIR / "profiles"
    profile_map  = {
        "arm64":  profiles_dir / "macos-arm64.r2",
        "x86_64": profiles_dir / "macos-x64.r2",
    }

    for arch, profile_path in profile_map.items():
        if not profile_path.exists():
            continue

        text     = profile_path.read_text()
        new_zo   = []
        for lib_name in LIB_ORDER:
            if not generated.get((lib_name, arch)):
                continue
            zsig_rel = f"macos/{arch}/{lib_name}.zsig"
            zo_line  = f"zo {zsig_rel}"
            if zo_line in text:
                continue   # already present
            new_zo.append(zo_line)

        if not new_zo:
            continue

        # Insert before the existing debian/ fallback zo block
        marker = "# No native macOS zsigs yet"
        if marker in text:
            insert_block = (
                "# Native macOS zsigs (compiled from Apple open source + SDK)\n"
                + "\n".join(new_zo)
                + "\n"
                # remove the old TODO comment
            )
            # Replace the old TODO comment and the following blank line
            text = text.replace(
                "# No native macOS zsigs yet (requires macOS SDK or Apple host).\n"
                "# Third-party libs compiled from identical source -- high cross-OS match rate.\n"
                "# Intentionally excluded: libstdc++ (macOS uses libc++ ABI).\n"
                "# TODO: replace with native macOS zsigs when macOS SDK becomes available.\n",
                insert_block
                + "# Third-party libs (statically linked OpenSSL, zlib, etc.)\n"
                + "# compiled from identical source — high cross-OS match rate:\n",
            )
        else:
            # Append before the first debian/ zo line
            first_debian = next(
                (i for i, l in enumerate(text.splitlines()) if l.startswith("zo debian/")),
                None
            )
            if first_debian is not None:
                lines = text.splitlines()
                lines[first_debian:first_debian] = (
                    ["# Native macOS zsigs"] + new_zo + [""]
                )
                text = "\n".join(lines) + "\n"

        profile_path.write_text(text)
        log(f"  Updated {profile_path.name}: added {new_zo}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def list_libs():
    print("Library targets:")
    print(f"  {'name':<15} {'source':<45} {'description'}")
    print("  " + "-" * 80)
    for name in LIB_ORDER:
        cfg = LIBS[name]
        print(f"  {name:<15} {cfg['org']}@{cfg['tag']:<25} {cfg['desc']}")
    print()
    print("Architectures:")
    for arch, cfg in ARCHES.items():
        print(f"  {arch:<10} {cfg['clang_target']:<35} {cfg['desc']}")


def main():
    global ZSIG_OUT_DIR
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--arch",        choices=list(ARCHES),
                    help="Target architecture (default: all)")
    ap.add_argument("--lib",         choices=LIB_ORDER, nargs="+",
                    help="Libraries to generate (default: all)")
    ap.add_argument("--sdk-version", default=SDK_DEFAULT_VERSION,
                    help=f"macOS SDK version (default: {SDK_DEFAULT_VERSION})")
    ap.add_argument("--sdk-path",
                    help="Use an already-extracted SDK dir instead of downloading")
    ap.add_argument("--output-dir",
                    help=f"Override output dir (default: {ZSIG_OUT_DIR})")
    ap.add_argument("--force",       action="store_true",
                    help="Regenerate even if output zsig already exists")
    ap.add_argument("--no-cache",    action="store_true",
                    help="Delete cached downloads and re-fetch everything")
    ap.add_argument("--no-update-profiles", action="store_true",
                    help="Skip updating macos-arm64.r2 / macos-x64.r2")
    ap.add_argument("--list",        action="store_true",
                    help="List available targets and exit")
    args = ap.parse_args()

    if args.list:
        list_libs()
        return

    arches    = [args.arch] if args.arch else list(ARCHES)
    libs_todo = args.lib or LIB_ORDER

    if args.output_dir:
        ZSIG_OUT_DIR = Path(args.output_dir)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if args.no_cache:
        # Remove SDK tarballs and source tarballs; keep extracted dirs so
        # re-extraction is avoided if the tarball itself is re-downloaded.
        for f in CACHE_DIR.glob("*.tar.xz"):
            f.unlink()
        for f in (CACHE_DIR / "src").glob("*.tar.gz"):
            f.unlink(missing_ok=True)
        log("Cache tarballs cleared.")

    print("=== macOS zsig generator ===")

    # ---------------------------------------------------------------------------
    # Step 1: verify clang supports at least one requested arch
    # ---------------------------------------------------------------------------
    for arch in arches:
        if not check_clang(arch):
            sys.exit(1)

    # ---------------------------------------------------------------------------
    # Step 2: download / locate SDK
    # ---------------------------------------------------------------------------
    if args.sdk_path:
        sdk_path = Path(args.sdk_path)
        if not sdk_path.exists():
            sys.exit(f"ERROR: --sdk-path {sdk_path} does not exist")
        log(f"  Using SDK: {sdk_path}")
    else:
        log(f"\n=== Downloading macOS SDK {args.sdk_version} ===")
        sdk_path = download_sdk(args.sdk_version, CACHE_DIR)
        if not sdk_path:
            sys.exit(
                "ERROR: SDK download failed.\n"
                "Alternatives:\n"
                "  --sdk-version 15.5   (or 15.2, 14.5, 13.3)\n"
                "  --sdk-path /path/to/MacOSX.sdk  (pre-extracted SDK dir)\n"
                "SDK sources:\n"
                "  https://github.com/joseluisq/macosx-sdks/releases\n"
            )

    # Verify SDK has headers
    if not (sdk_path / "usr" / "include").exists():
        sys.exit(f"ERROR: SDK at {sdk_path} is missing usr/include")

    # ---------------------------------------------------------------------------
    # Step 3: generate zsigs
    # ---------------------------------------------------------------------------
    generated: dict[tuple[str, str], bool] = {}

    total = ok = 0
    for arch in arches:
        log(f"\n=== {arch} ({ARCHES[arch]['desc']}) ===")
        for lib_name in libs_todo:
            total += 1
            try:
                success = generate_one(lib_name, arch, sdk_path, args.force)
                generated[(lib_name, arch)] = success
                if success:
                    ok += 1
            except Exception as exc:
                import traceback
                log(f"  {lib_name}/{arch}: EXCEPTION: {exc}")
                traceback.print_exc()
                generated[(lib_name, arch)] = False

    # ---------------------------------------------------------------------------
    # Step 4: update profiles
    # ---------------------------------------------------------------------------
    if not args.no_update_profiles and any(generated.values()):
        log("\n=== Updating macOS profiles ===")
        update_profiles(generated)

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    print(f"\n{'='*50}")
    print(f"Done: {ok}/{total} succeeded")
    for (lib_name, arch), success in sorted(generated.items()):
        status = "✓" if success else "✗"
        zsig = ZSIG_OUT_DIR / arch / f"{lib_name}.zsig"
        size = f"  {zsig.stat().st_size:,} bytes" if zsig.exists() else ""
        print(f"  {status} {arch}/{lib_name}{size}")

    if ok < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
