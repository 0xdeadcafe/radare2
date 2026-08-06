#!/usr/bin/env bash
# fetch-windows-pdbs.sh — Download PDB symbol files for Windows PE binaries.
#
# Wraps download-pdb.py and stores PDBs in the standard corpus cache so
# r2's pdb.autoload=1 setting can find them automatically.
#
# Usage:
#   fetch-windows-pdbs.sh [dll_or_dir]
#       dll_or_dir  - Single DLL/EXE file, or directory to scan recursively.
#                     Defaults to current directory if omitted.
#
# PDB cache location: ~/.local/share/radare2/cache/pdb/
# (set via pdb.symstore in ~/.radare2rc.local — auto-configured by install.sh)
#
# r2 auto-loading:
#   pdb.autoload=1 is set in ~/.radare2rc.local by install.sh.
#   When you open a Windows PE, r2 checks pdb.symstore, then queries
#   pdb.server (Microsoft symbol server) if not found locally.
#   Use 'idp' inside r2 to load the PDB for the current binary manually.
#
# Examples:
#   fetch-windows-pdbs.sh target.dll          # download one PDB
#   fetch-windows-pdbs.sh /mnt/firmware/bin/  # batch all DLLs in directory
#   fetch-windows-pdbs.sh                     # batch current directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${HOME}/.local/share/radare2/cache/pdb"
DOWNLOADER="${SCRIPT_DIR}/download-pdb.py"

if [[ ! -f "${DOWNLOADER}" ]]; then
    echo "ERROR: download-pdb.py not found at ${DOWNLOADER}" >&2
    exit 1
fi

INPUT="${1:-.}"

mkdir -p "${CACHE_DIR}"

if [[ -f "${INPUT}" ]]; then
    echo "Fetching PDB for: ${INPUT}"
    python3 "${DOWNLOADER}" "${INPUT}" --output-dir "${CACHE_DIR}"
elif [[ -d "${INPUT}" ]]; then
    echo "Batch fetching PDBs from: ${INPUT}"
    echo "PDB cache: ${CACHE_DIR}"
    python3 "${DOWNLOADER}" --batch "${INPUT}" --output-dir "${CACHE_DIR}"
else
    echo "Usage: $(basename "${BASH_SOURCE[0]}") [dll_or_exe_or_dir]"
    echo ""
    echo "Downloads PDB symbol files from Microsoft symbol server."
    echo "PDB cache: ${CACHE_DIR}"
    echo ""
    echo "r2 PDB configuration (from ~/.radare2rc.local):"
    echo "  pdb.autoload=1      — auto-download on PE open"
    echo "  pdb.symstore=${CACHE_DIR}"
    echo "  pdb.server=https://msdl.microsoft.com/download/symbols"
    echo ""
    echo "Manual load inside r2: idp [file.pdb]"
    exit 1
fi
