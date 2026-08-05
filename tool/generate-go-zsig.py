#!/usr/bin/env python3
"""
Generate r2 zignatures from Go standard library.

Builds a small Go binary that forces stdlib packages to link, then
generates zsigs from the symbol-rich resulting binary.

Requirements:
    - Go toolchain (https://go.dev/dl/ or system package)
    - Python 3.8+
    - r2pipe

Usage:
    generate-go-zsig.py --arch amd64
    generate-go-zsig.py --arch arm64
    generate-go-zsig.py --arch 386
    generate-go-zsig.py --all
    generate-go-zsig.py --go /usr/local/go/bin/go --arch amd64
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR", Path.home() / ".local" / "share" / "radare2"))
ZSIG_OUTPUT_DIR = R2_DATA_DIR / "zigns" / "go"

# Minimal Go source that forces stdlib packages to be linked
GO_SOURCE = '''
package main

import (
    "crypto/aes"; "crypto/cipher"; "crypto/hmac"
    "crypto/md5"; "crypto/rand"; "crypto/sha256"
    "crypto/sha512"; "crypto/tls"; "crypto/x509"
    "encoding/base64"; "encoding/hex"; "encoding/json"
    "fmt"; "io"; "net"; "net/http"; "os"; "os/exec"
    "path/filepath"; "regexp"; "strings"; "sync"; "time"
)

func main() {
    _ = aes.NewCipher; _ = cipher.NewGCM; _ = hmac.New
    _ = md5.New; _ = rand.Reader; _ = sha256.New
    _ = sha512.New; _ = tls.Dial; _ = x509.NewCertPool
    _ = base64.StdEncoding.EncodeToString; _ = hex.EncodeToString
    _ = json.Marshal; _ = fmt.Println; _ = io.ReadAll
    _ = net.Dial; _ = http.Get; _ = os.Open; _ = exec.Command
    _ = filepath.Join; _ = regexp.Compile
    _ = strings.Builder{}; _ = sync.Mutex{}; _ = time.Now
}
'''

ARCH_TO_GOARCH = {
    "amd64": "amd64",
    "arm64": "arm64",
    "x86": "386",
    "386": "386",
    "riscv64": "riscv64",
    "ppc64le": "ppc64le",
    "s390x": "s390x",
    "mips": "mipsle",
    "mips64": "mips64le",
}

def find_go() -> str:
    for candidate in ["/usr/local/go/bin/go", shutil.which("go"), "go"]:
        if candidate and Path(candidate).exists():
            return candidate
    return "go"


def build_stdlib_binary(go_bin: str, arch: str, tmpdir: str) -> Path:
    goarch = ARCH_TO_GOARCH.get(arch, arch)
    src = Path(tmpdir) / "main.go"
    src.write_text(GO_SOURCE)
    out = Path(tmpdir) / f"go_stdlib_{arch}"
    env = os.environ.copy()
    env["GOOS"] = "linux"
    env["GOARCH"] = goarch
    result = subprocess.run(
        [go_bin, "build", "-gcflags=-N -l", "-o", str(out), str(src)],
        capture_output=True, text=True, env=env
    )
    if result.returncode != 0:
        print(f"  Build failed: {result.stderr.strip()}", file=sys.stderr)
        return None
    return out


def generate(go_bin: str, arch: str, output_dir: Path = None) -> bool:
    output_dir = output_dir or ZSIG_OUTPUT_DIR
    print(f"\n=== Go 1.x stdlib zsig for {arch} ===")
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen", SCRIPT_DIR / "generate-zsig.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    with tempfile.TemporaryDirectory() as tmpdir:
        binary = build_stdlib_binary(go_bin, arch, tmpdir)
        if not binary:
            return False
        print(f"  Built: {binary} ({binary.stat().st_size:,} bytes)")
        out_path = output_dir / arch / "go1.23-stdlib.zsig"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        success, count = gen.generate_zsig_from_lib(str(binary), str(out_path), prefix="")
        if success:
            print(f"  Output: {out_path} ({count} sigs)")
        return success


def main():
    ap = argparse.ArgumentParser(description="Generate Go stdlib zsigs for r2")
    ap.add_argument("--go", default=find_go(), help="Path to Go binary")
    ap.add_argument("--arch", choices=list(ARCH_TO_GOARCH), help="Target architecture")
    ap.add_argument("--all", action="store_true", help="Generate for common arches")
    ap.add_argument("--output-dir", help="Override output directory")
    args = ap.parse_args()

    outdir = Path(args.output_dir) if args.output_dir else ZSIG_OUTPUT_DIR
    arches = list(ARCH_TO_GOARCH.keys()) if args.all else ([args.arch] if args.arch else None)
    if not arches:
        ap.print_help()
        sys.exit(1)

    ok = sum(generate(args.go, a, outdir) for a in arches)
    print(f"\n=== Done: {ok}/{len(arches)} ===")


if __name__ == "__main__":
    main()
