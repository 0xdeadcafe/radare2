"""Shared utilities for zsig generation scripts.

Used by:
- generate-zsig.py (Linux deb packages)
- generate-musl-zsig.py (musl libc)
- generate-ndk-zsig.py (Android NDK)
- generate-winsdk-zsig.py (Windows SDK)
- generate-vcruntime-zsig.py (VC++ runtime)

Timeout Configuration:
    Set R2_ZSIG_TIMEOUT environment variable to override default timeouts.
    Value is in seconds (default: 60 for object files).

Output Directory Configuration:
    Set R2_ZSIG_DIR environment variable to override default zsig output location.
    Default: ./zigns (relative to project root) or ~/.local/share/radare2/zigns
"""
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Generator

try:
    import r2pipe
except ImportError:
    print("Error: r2pipe not installed. Run: pip install r2pipe", file=sys.stderr)
    sys.exit(1)

# Default timeout for processing object files (seconds)
# Can be overridden with R2_ZSIG_TIMEOUT environment variable
DEFAULT_TIMEOUT = int(os.environ.get("R2_ZSIG_TIMEOUT", "60"))

# Base directories for radare2 data
# R2_DATA_DIR: General r2 data (caches, downloads)
# R2_ZSIG_DIR: Specifically for zsig output (overrides default location)
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))


def get_zsig_output_dir(subdir: str = None) -> Path:
    """Get the zsig output directory, respecting environment variables.
    
    Priority:
    1. R2_ZSIG_DIR environment variable (if set)
    2. ./zigns relative to script location (if exists)
    3. R2_DATA_DIR/zigns (default ~/.local/share/radare2/zigns)
    
    Args:
        subdir: Optional subdirectory (e.g., "android", "windows", "debian/amd64")
        
    Returns:
        Path to the output directory
    """
    # Check for explicit override
    if "R2_ZSIG_DIR" in os.environ:
        base = Path(os.environ["R2_ZSIG_DIR"])
    else:
        # Check if we're in a project with a zigns directory
        script_dir = Path(__file__).parent
        project_zigns = script_dir.parent / "zigns"
        if project_zigns.exists():
            base = project_zigns
        else:
            base = R2_DATA_DIR / "zigns"
    
    if subdir:
        return base / subdir
    return base


def get_cache_dir(subdir: str = None) -> Path:
    """Get the cache directory for downloads and temporary files.
    
    Args:
        subdir: Optional subdirectory (e.g., "vcredist", "winsdk", "ndk")
        
    Returns:
        Path to the cache directory
    """
    base = R2_DATA_DIR / "cache"
    if subdir:
        return base / subdir
    return base


# ============================================================================
# Tool availability checks
# ============================================================================

def require_tools(tools: list[str], install_hint: str = None) -> None:
    """Check for required tools and exit with helpful message if missing."""
    missing = [t for t in tools if not shutil.which(t)]
    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}", file=sys.stderr)
        if install_hint:
            print(f"Install with: {install_hint}", file=sys.stderr)
        sys.exit(1)


@contextmanager
def open_r2(path: str, flags: list[str] = None) -> Generator:
    """Context manager for r2pipe sessions.
    
    Ensures r2.quit() is called even if an exception occurs.
    
    Args:
        path: Path to binary or "malloc://N" for empty session
        flags: Optional r2 flags (default: ["-2"] for no stderr)
        
    Yields:
        r2pipe instance
        
    Example:
        with open_r2("malloc://1") as r2:
            r2.cmd("zo signatures.zsig")
            count = r2.cmd("z~?")
    """
    r2 = r2pipe.open(path, flags=flags or ["-2"])
    try:
        yield r2
    finally:
        try:
            r2.quit()
        except Exception:
            pass


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run command with reasonable defaults."""
    return subprocess.run(cmd, capture_output=True, **kwargs)


def extract_objects_from_archive(archive_path: str, work_dir: str) -> list[str]:
    """Extract .o/.lo/.os files from a static archive (.a file).

    .os = Position-Independent Code (PIC) objects, used by uClibc-ng and
    some other embedded toolchains (e.g. Bootlin AArch64 uclibc sysroots).
    These are functionally identical to .o files for signature generation.
    
    Args:
        archive_path: Path to the .a archive file
        work_dir: Directory to extract objects into
        
    Returns:
        List of paths to extracted object files
    """
    result = run(["ar", "t", archive_path])
    if result.returncode != 0:
        return []
    
    members = result.stdout.decode().strip().split('\n')
    object_files = [m for m in members
                    if m.endswith('.o') or m.endswith('.lo') or m.endswith('.os')]
    
    if not object_files:
        return []
    
    extract_dir = os.path.join(work_dir, Path(archive_path).stem + "_objects")
    os.makedirs(extract_dir, exist_ok=True)
    
    result = run(["ar", "x", archive_path], cwd=extract_dir)
    if result.returncode != 0:
        return []
    
    extracted = []
    for obj in object_files:
        obj_path = os.path.join(extract_dir, obj)
        if os.path.exists(obj_path):
            extracted.append(obj_path)
    
    return extracted


def count_signatures(r2) -> int:
    """Count signatures in current r2 session.
    
    Uses z~? which reliably counts loaded signatures.
    
    Args:
        r2: Open r2pipe instance
        
    Returns:
        Number of signatures loaded
    """
    sig_count_str = r2.cmd("z~?")
    try:
        return int(sig_count_str.strip()) if sig_count_str.strip() else 0
    except ValueError:
        return 0


def _generate_zsig_from_object(
    obj_path: str, 
    zsig_path: str, 
    prefix: str,
    log: Callable[[str], None] = None,
    timeout: int = None
) -> tuple[bool, int]:
    """Generate zsig from a single object file.
    
    Args:
        obj_path: Path to .o/.obj file
        zsig_path: Output path for .zsig file
        prefix: Signature prefix (e.g., "musl", "ndk_c")
        log: Optional logging function
        timeout: Maximum seconds per object file (default: DEFAULT_TIMEOUT or R2_ZSIG_TIMEOUT env)
        
    Returns:
        Tuple of (success, signature_count)
    """
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    
    # Use subprocess with timeout to avoid hanging on complex objects
    r2_script = f'e zign.prefix={prefix}; aa; zg; z~?; zos {zsig_path}'
    try:
        result = subprocess.run(
            ['r2', '-q0', '-c', r2_script, obj_path],
            capture_output=True,
            timeout=timeout,
            text=True
        )
        
        if result.returncode != 0:
            return False, 0
        
        # Parse signature count from output (z~? prints count)
        lines = result.stdout.strip().split('\n')
        sig_count = 0
        for line in lines:
            try:
                sig_count = int(line.strip())
                break
            except ValueError:
                continue
        
        if sig_count > 0 and os.path.exists(zsig_path) and os.path.getsize(zsig_path) > 0:
            return True, sig_count
        return False, 0
        
    except subprocess.TimeoutExpired:
        if log:
            log(f"Timeout processing {Path(obj_path).name} (>{timeout}s)")
        return False, 0
    except Exception as e:
        if log:
            log(f"Error processing {obj_path}: {type(e).__name__}: {e}")
        return False, 0


def merge_zsigs(
    zsig_files: list[str], 
    output_path: str,
    log: Callable[[str], None] = None,
    chunk_size: int = 50
) -> tuple[bool, int]:
    """Merge multiple zsig files into one.

    Args:
        zsig_files: List of paths to zsig files to merge
        output_path: Output path for merged zsig
        log: Optional logging function
        chunk_size: Unused, kept for call-site compatibility
        
    Returns:
        Tuple of (success, signature_count)
    """
    if not zsig_files:
        return False, 0
    
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    if len(zsig_files) == 1:
        shutil.copy(zsig_files[0], output_path)
        # verify_zsig: simple existence + size check
        exists = os.path.exists(output_path) and os.path.getsize(output_path) > 0
        sig_count = 0
        if exists:
            try:
                with open_r2("malloc://1") as r2:
                    r2.cmd(f"zo {output_path}")
                    sig_count = count_signatures(r2)
            except Exception:
                sig_count = 1  # file exists, count unknown
        return exists, sig_count
    
    return _merge_zsigs_simple(zsig_files, output_path, log)


def _merge_zsigs_simple(
    zsig_files: list[str], 
    output_path: str,
    log: Callable[[str], None] = None
) -> tuple[bool, int]:
    """Simple merge - load all zsigs in one r2 session and save.
    
    This can fail silently for very large signature sets (>100k).
    """
    try:
        with open_r2("malloc://1") as r2:
            for zsig in zsig_files:
                r2.cmd(f"zo {zsig}")
            
            sig_count = count_signatures(r2)
            r2.cmd(f"zos {output_path}")
            
            if os.path.exists(output_path):
                return True, sig_count
            return False, 0
    except Exception as e:
        if log:
            log(f"Merge failed: {type(e).__name__}: {e}")
        return False, 0


def generate_zsig_batch(
    object_files: list[str], 
    output_path: str, 
    prefix: str = "zsig",
    batch_size: int = 100,
    log: Callable[[str], None] = None,
    progress: Callable[[int, int, int], None] = None
) -> tuple[bool, int]:
    """Generate zsig from object files using batched processing.
    
    This is more memory-efficient for large numbers of objects.
    
    Args:
        object_files: List of paths to object files
        output_path: Output path for final zsig
        prefix: Signature prefix
        batch_size: Number of objects per batch (default 100)
        log: Optional logging function
        progress: Optional progress callback(batch_num, total_batches, batch_sigs)
        
    Returns:
        Tuple of (success, signature_count)
    """
    if log:
        log(f"Processing {len(object_files)} object files...")
    
    work_dir = tempfile.mkdtemp()
    batch_zsigs = []
    total = len(object_files)
    total_sigs = 0
    failed_objects = 0
    
    try:
        for batch_start in range(0, total, batch_size):
            batch_end = min(batch_start + batch_size, total)
            batch = object_files[batch_start:batch_end]
            batch_num = batch_start // batch_size + 1
            total_batches = (total + batch_size - 1) // batch_size
            
            if log:
                log(f"  Batch {batch_num}/{total_batches} ({batch_start}-{batch_end})...")
            
            zsigs = []
            batch_sigs = 0
            
            for obj_path in batch:
                obj_name = Path(obj_path).stem
                zsig_path = os.path.join(work_dir, f"obj_{obj_name}.zsig")
                
                success, sig_count = _generate_zsig_from_object(obj_path, zsig_path, prefix)
                if success:
                    zsigs.append(zsig_path)
                    batch_sigs += sig_count
                else:
                    failed_objects += 1
            
            # Merge this batch
            total_sigs += batch_sigs
            if zsigs:
                batch_zsig = os.path.join(work_dir, f"batch_{batch_start}.zsig")
                try:
                    with open_r2("malloc://1") as r2:
                        for z in zsigs:
                            r2.cmd(f"zo {z}")
                        r2.cmd(f"zos {batch_zsig}")
                    if os.path.exists(batch_zsig):
                        batch_zsigs.append(batch_zsig)
                        if progress:
                            progress(batch_num, total_batches, batch_sigs)
                except Exception as e:
                    if log:
                        log(f"    Batch merge failed: {type(e).__name__}: {e}")
        
        if not batch_zsigs:
            if log and failed_objects > 0:
                log(f"  WARNING: {failed_objects} objects failed to process")
            return False, 0
        
        if log:
            log(f"  Merging {len(batch_zsigs)} batches ({total_sigs} total signatures)...")
            if failed_objects > 0:
                log(f"  WARNING: {failed_objects} objects failed to process")
        
        # Final merge
        success, final_count = merge_zsigs(batch_zsigs, output_path, log=log)
        
        if success:
            # Use final_count if available, otherwise use accumulated total
            return True, final_count if final_count > 0 else total_sigs
        return False, 0
        
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def check_symbols(lib_path: str) -> int:
    """Check how many text symbols a library has.
    
    Args:
        lib_path: Path to library file
        
    Returns:
        Count of text symbols (functions)
    """
    result = run(["nm", str(lib_path)])
    if result.returncode != 0:
        return 0
    return result.stdout.count(b" T ")


def generate_zsig_from_dll(
    dll_path: str,
    zsig_path: str,
    prefix: str = None,
    log: Callable[[str], None] = None,
    timeout: int = 300
) -> tuple[bool, int]:
    """Generate zsig from a Windows DLL/PE file.
    
    Uses radare2 to analyze the PE file and generate function signatures.
    PE analysis requires full analysis (aaa) rather than just linear sweep.
    
    Args:
        dll_path: Path to .dll or .exe PE file
        zsig_path: Output path for .zsig file
        prefix: Signature prefix (derived from filename if None)
        log: Optional logging function
        timeout: Maximum seconds for analysis (default: 300, PEs can be slow)
        
    Returns:
        Tuple of (success, signature_count)
    """
    dll_name = Path(dll_path).stem
    if prefix is None:
        prefix = dll_name.lower().replace("-", "_")
    
    # Use subprocess with timeout to avoid hanging on complex PEs
    r2_script = f'e zign.prefix={prefix}; aaa; zg; z~?; zos {zsig_path}'
    try:
        result = subprocess.run(
            ['r2', '-q0', '-c', r2_script, dll_path],
            capture_output=True,
            timeout=timeout,
            text=True
        )
        
        if result.returncode != 0:
            if log:
                log(f"r2 analysis failed for {dll_name}: {result.stderr[:200]}")
            return False, 0
        
        # Parse signature count from output (z~? prints count)
        lines = result.stdout.strip().split('\n')
        sig_count = 0
        for line in lines:
            try:
                sig_count = int(line.strip())
                break
            except ValueError:
                continue
        
        if sig_count > 0 and os.path.exists(zsig_path) and os.path.getsize(zsig_path) > 0:
            return True, sig_count
        return False, 0
        
    except subprocess.TimeoutExpired:
        if log:
            log(f"Timeout processing {dll_name} (>{timeout}s)")
        return False, 0
    except Exception as e:
        if log:
            log(f"Error processing {dll_path}: {type(e).__name__}: {e}")
        return False, 0


def generate_zsig_from_lib(
    lib_path: str, 
    zsig_path: str, 
    work_dir: str = None,
    prefix: str = None,
    log: Callable[[str], None] = None
) -> tuple[bool, int]:
    """Generate zsig from a library file (.a or .so).
    
    For .a archives, extracts .o files to preserve symbols.
    
    Args:
        lib_path: Path to library file
        zsig_path: Output path for zsig
        work_dir: Working directory (created if None)
        prefix: Signature prefix (derived from lib name if None)
        log: Optional logging function
        
    Returns:
        Tuple of (success, signature_count)
    """
    lib_stem = Path(lib_path).stem
    if prefix is None:
        prefix = lib_stem[3:] if lib_stem.startswith("lib") else lib_stem
    
    cleanup_work_dir = False
    if work_dir is None:
        work_dir = tempfile.mkdtemp()
        cleanup_work_dir = True
    
    try:
        if not lib_path.endswith('.a'):
            # For .so files, analyze directly
            try:
                with open_r2(lib_path) as r2:
                    r2.cmd(f"e zign.prefix={prefix}")
                    r2.cmd("aa")
                    r2.cmd("zg")
                    
                    sig_count = count_signatures(r2)
                    
                    if sig_count > 0:
                        os.makedirs(os.path.dirname(os.path.abspath(zsig_path)), exist_ok=True)
                        r2.cmd(f"zos {zsig_path}")
                        return os.path.exists(zsig_path), sig_count
                    else:
                        return False, 0
            except Exception as e:
                if log:
                    log(f"Error processing {lib_path}: {type(e).__name__}: {e}")
                return False, 0
        
        # For .a archives, extract .o files
        object_files = extract_objects_from_archive(lib_path, work_dir)
        if not object_files:
            return False, 0
        
        # Generate zsig from each .o file
        part_zsigs = []
        total_sigs = 0
        for obj_path in object_files:
            obj_name = Path(obj_path).stem
            part_zsig = os.path.join(work_dir, f"{obj_name}.zsig")
            success, sig_count = _generate_zsig_from_object(obj_path, part_zsig, prefix)
            if success:
                part_zsigs.append(part_zsig)
                total_sigs += sig_count
        
        if not part_zsigs:
            return False, 0
        
        # Merge all zsigs
        os.makedirs(os.path.dirname(os.path.abspath(zsig_path)), exist_ok=True)
        return merge_zsigs(part_zsigs, zsig_path, log=log)
        
    finally:
        if cleanup_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)


def generate_zsig_from_libc_dir(
    libc_dir: str,
    zsig_path: str,
    prefix: str = None,
    log: Callable[[str], None] = None,
) -> tuple[bool, int]:
    """Generate a merged zsig from all .a libraries found in a directory tree.

    This is the entry point used by generate-musl-zsig.py after downloading
    and extracting a musl-dev (or similar) package.

    Args:
        libc_dir:  Directory containing .a static library files.
        zsig_path: Output path for the merged zsig.
        prefix:    Signature prefix.  If None each library uses its own stem.
        log:       Optional logging function.

    Returns:
        Tuple of (success, total_signature_count).
    """
    lib_dir = Path(libc_dir)
    lib_files = sorted(lib_dir.rglob("*.a"))

    if not lib_files:
        if log:
            log(f"generate_zsig_from_libc_dir: no .a files found in {libc_dir}")
        return False, 0

    if log:
        log(f"generate_zsig_from_libc_dir: found {len(lib_files)} libraries in {libc_dir}")

    part_zsigs: list[str] = []
    total_sigs = 0

    with tempfile.TemporaryDirectory() as work_dir:
        for lib in lib_files:
            lib_prefix = prefix
            if lib_prefix is None:
                stem = lib.stem
                lib_prefix = stem[3:] if stem.startswith("lib") else stem

            part_path = os.path.join(work_dir, f"{lib.stem}.zsig")
            ok, n = generate_zsig_from_lib(
                str(lib), part_path, prefix=lib_prefix, log=log
            )
            if ok:
                part_zsigs.append(part_path)
                total_sigs += n
                if log:
                    log(f"  {lib.name}: {n} signatures")
            else:
                if log:
                    log(f"  {lib.name}: skipped (no symbols or too few)")

        if not part_zsigs:
            if log:
                log("generate_zsig_from_libc_dir: no usable libraries")
            return False, 0

        os.makedirs(os.path.dirname(os.path.abspath(zsig_path)), exist_ok=True)
        ok, final_count = merge_zsigs(part_zsigs, zsig_path, log=log)
        if log:
            log(f"generate_zsig_from_libc_dir: merged → {zsig_path} ({final_count} sigs)")
        return ok, final_count
