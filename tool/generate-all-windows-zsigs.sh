#!/bin/bash
# Generate all Windows VC++ runtime zsigs in parallel
# Usage: ./generate-all-windows-zsigs.sh [--parallel N]

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PARALLEL=4  # Default parallel jobs

while [[ $# -gt 0 ]]; do
    case "$1" in
        --parallel)
            PARALLEL="$2"; shift 2 ;;
        *)
            echo "Unknown option: $1"; echo "Usage: $0 [--parallel N]"; exit 1 ;;
    esac
done

# Default cache dir matches download-vcredist.py default
R2_DATA_DIR="${R2_DATA_DIR:-$HOME/.local/share/radare2}"
VCREDIST_CACHE="${R2_DATA_DIR}/cache/vcredist"

# Versions and architectures to process
# arm64 MSVC target only exists from VS2017 onward
VERSIONS="2008 2010 2012 2013 2015 2017 2019 2022"
ARCHES="x86 x64 arm64"
ARM64_MIN_VERSION=2017

# Create list of jobs
jobs_file=$(mktemp)
for version in $VERSIONS; do
    for arch in $ARCHES; do
        # arm64 didn't exist before VS2017
        if [ "$arch" = "arm64" ] && [ "$version" -lt "$ARM64_MIN_VERSION" ]; then
            continue
        fi
        extracted_dir="${VCREDIST_CACHE}/$version/$arch/extracted"
        if [ -d "$extracted_dir" ] && ls "$extracted_dir"/*.dll >/dev/null 2>&1; then
            output_dir="zigns/windows/$arch"
            output_file="$output_dir/vs${version}-vcruntime140.zsig"
            if [ ! -f "$output_file" ]; then
                echo "$version $arch" >> "$jobs_file"
            else
                echo "SKIP: $output_file already exists"
            fi
        fi
    done
done

echo "=== Jobs to run ==="
cat "$jobs_file"
echo ""

# Process jobs
process_job() {
    version=$1
    arch=$2
    script_dir=$3
    echo "[START] VS$version $arch"
    python3 "${script_dir}/tool/generate-vcruntime-zsig.py" --version "$version" --arch "$arch" \
        --output-dir "${script_dir}/zigns/windows" 2>&1 | tail -5
    echo "[DONE] VS$version $arch"
}
export -f process_job

if command -v parallel >/dev/null 2>&1; then
    parallel -j "$PARALLEL" --colsep ' ' process_job {1} {2} "$SCRIPT_DIR" :::: "$jobs_file"
else
    # Fallback: run sequentially
    while read -r version arch; do
        process_job "$version" "$arch" "$SCRIPT_DIR"
    done < "$jobs_file"
fi

rm -f "$jobs_file"

echo ""
echo "=== Generated zsigs ==="
find zigns/windows -name "*.zsig" -exec ls -lh {} \;
