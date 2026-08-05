#!/usr/bin/env python3
"""
ios_string_labeler.py — Label Cisco IOS MIPS32-BE functions via debug strings.

Key discovery: IOS C1900 is compiled for base 0x21000000, NOT the ELF VA 0x81000000.
(KSEG0 0x81000000 = phys 0x01000000, but linker base is 0x21000000)

The jal targets confirm: 0x21000000-0x27BC1774 is the real code+data range.
Memory map at real base:
  .text:   0x21000000 - 0x24F57FFF
  .rodata: 0x24F58000 - 0x26981BFF
  .data:   0x26981C70 - 0x277CD3DF
"""

import struct
import re
import sys
import os
import json
from collections import defaultdict

BINARY    = sys.argv[1]
OUTPUT_R2 = sys.argv[2]
OUTPUT_JSON = sys.argv[3] if len(sys.argv) > 3 else None

# ─── Address mapping ─────────────────────────────────────────────────────────
# The REAL base used by the compiled code (NOT the ELF VA)
REAL_BASE = 0x21000000
FILE_OFF  = 0x60

# ELF VA base (for r2 which loads at this address)
ELF_VA_BASE = 0x81000000
# Delta: to convert real addresses to r2/ELF addresses
VA_DELTA = ELF_VA_BASE - REAL_BASE  # 0x60000000

TEXT_SIZE   = 0x3F58000
RODATA_OFF  = 0x3F58060   # file offset of rodata
RODATA_SIZE = 0x1A29C00
DATA_OFF    = 0x5981CD0
DATA_SIZE   = 0x0E4B770

TEXT_REAL_START   = REAL_BASE
TEXT_REAL_END     = REAL_BASE + TEXT_SIZE
RODATA_REAL_START = REAL_BASE + (RODATA_OFF - FILE_OFF)
RODATA_REAL_END   = RODATA_REAL_START + RODATA_SIZE
DATA_REAL_START   = REAL_BASE + (DATA_OFF - FILE_OFF)
DATA_REAL_END     = DATA_REAL_START + DATA_SIZE

# MIPS prologue
PROLOGUE_ADDIU_SP = 0x27BD
MAX_PROLOGUE_SEARCH = 8192  # bytes backward

def off_to_rva(off):
    """File offset → real VA (as compiled)."""
    return off - FILE_OFF + REAL_BASE

def rva_to_off(rva):
    """Real VA → file offset."""
    return rva - REAL_BASE + FILE_OFF

def rva_to_elfva(rva):
    """Real VA → ELF/r2 VA."""
    return rva + VA_DELTA

def read_u32be(data, off):
    if off + 4 > len(data):
        return None
    return struct.unpack('>I', data[off:off+4])[0]


# ─── Step 1: Extract labeled strings ────────────────────────────────────────

# Patterns for label extraction (compiled once)
PAT_VIEW_ROOT = re.compile(r'VIEW_ROOT/.*?([^/]+)\.c$')
PAT_FUNCNAME  = re.compile(r'^([a-z_][a-z0-9_]{4,})\(\)')
PAT_OPENSSL   = re.compile(r'^((?:ASN1|BIO|BN|BUF|COMP|CONF|CRYPTO|DH|DSA|DSO|EC|ENGINE|ERR|EVP|OBJ|OCSP|PEM|PKCS[0-9]*|RAND|RSA|SSL|UI|X509|X509V3)_[A-Za-z_][A-Za-z0-9_]*)$')

# Subsystem prefixes to auto-label
SUBSYSTEM_PREFIXES = [
    'smi_', 'ikev2_', 'crypto_', 'cwmp_', 'http_', 'snmp_', 'snmpd_',
    'ipsec_', 'sip_', 'isakmp_', 'aaa_', 'radius_', 'dhcp_', 'dhcpd_',
    'ssh_', 'dns_', 'ospf_', 'ospfv3_', 'bgp_', 'eigrp_', 'fib_',
    'tftp_', 'telnet_', 'cdp_', 'lldp_', 'ntp_', 'pki_', 'rsa_',
    'adj_', 'cef_', 'mpls_', 'ldp_', 'lisp_', 'mfib_', 'nat_',
    'emweb_', 'fh_', 'cli_', 'parser_', 'netconf_', 'wsma_',
    'cns_', 'gsi_', 'beep_', 'soap_', 'xml_', 'odm_',
    'process_', 'chunk_', 'pool_', 'buffer_',
    'reg_invoke_', 'platform_', 'hw_api_',
    'ike_', 'srtp_', 'sctp_', 'rtp_',
    'acl_', 'qos_', 'policy_', 'class_',
    'vrf_', 'rib_', 'route_',
    'license_', 'call_home_',
    'insp_sip_', 'insp_',
]

# Debug message pattern: "SUBSYS: funcname"
PAT_DEBUG_MSG = re.compile(r'^([A-Z][A-Z0-9_]{2,}): ([a-z_][a-z0-9_]{5,})[\s:(]')

# Combine all subsystem patterns into one regex for speed
SUBSYS_RE = re.compile(r'^(' + '|'.join(re.escape(p) for p in SUBSYSTEM_PREFIXES) + r')[a-z0-9_]{3,}$')

SOURCE_PRIORITY = {
    'funcname_parens': 10,
    'openssl_api': 9,
    'subsystem': 8,
    'debug_msg': 7,
    'process_name': 7,
    'VIEW_ROOT': 5,
}


def extract_labeled_strings(data):
    """Scan rodata and data sections for debug strings that reveal function/symbol names."""
    results = []

    sections = [
        (RODATA_OFF, RODATA_SIZE, RODATA_REAL_START, 'rodata'),
        (DATA_OFF, DATA_SIZE, DATA_REAL_START, 'data'),
    ]

    for sec_file_off, sec_size, sec_rva_start, sec_name in sections:
        section = data[sec_file_off:sec_file_off + sec_size]
        print(f"  Scanning .{sec_name} ({sec_size:,} bytes, RVA 0x{sec_rva_start:08x})...",
              file=sys.stderr)

        i = 0
        while i < len(section):
            if section[i] < 0x20 or section[i] > 0x7E:
                i += 1
                continue
            end = i
            while end < len(section) and section[end] != 0:
                end += 1
            slen = end - i
            if slen < 6:
                i = end + 1
                continue

            try:
                s = section[i:end].decode('ascii')
            except:
                i = end + 1
                continue

            string_rva = sec_rva_start + i
            label = None
            source = None

            # Pattern 1: VIEW_ROOT
            m = PAT_VIEW_ROOT.search(s)
            if m:
                label = f"src_{m.group(1)}"
                source = 'VIEW_ROOT'

            # Pattern 2: funcname()
            if not label:
                m = PAT_FUNCNAME.match(s)
                if m:
                    label = m.group(1)
                    source = 'funcname_parens'

            # Pattern 3: OpenSSL API
            if not label:
                m = PAT_OPENSSL.match(s)
                if m:
                    label = f"ossl_{m.group(1)}"
                    source = 'openssl_api'

            # Pattern 4: Subsystem prefix
            if not label:
                m = SUBSYS_RE.match(s)
                if m:
                    label = s
                    source = 'subsystem'

            # Pattern 5: "SUBSYS: funcname" debug message
            if not label:
                m = PAT_DEBUG_MSG.match(s)
                if m:
                    label = m.group(2)
                    source = 'debug_msg'

            if label:
                results.append((string_rva, label, source, s[:80]))

            i = end + 1

    print(f"  Total labeled strings: {len(results)}", file=sys.stderr)
    return results


# ─── Step 2: Find MIPS lui/addiu xrefs ──────────────────────────────────────

def find_string_refs(data, labeled_strings):
    """
    For each (string_rva, label, ...), find lui/addiu pairs in .text that
    load the string's real VA.
    Returns: list of (ref_rva, string_rva, label, source)
    """
    # Build: lui_imm → [(addiu_imm, string_rva, label, source), ...]
    hi_lo_map = defaultdict(list)
    for string_rva, label, source, _ in labeled_strings:
        hi = (string_rva >> 16) & 0xFFFF
        lo = string_rva & 0xFFFF
        if lo >= 0x8000:
            lui_imm = (hi + 1) & 0xFFFF
        else:
            lui_imm = hi
        hi_lo_map[lui_imm].append((lo & 0xFFFF, string_rva, label, source))

    print(f"  Unique lui targets to search: {len(hi_lo_map)}", file=sys.stderr)

    text_file_start = FILE_OFF
    text_file_end = FILE_OFF + TEXT_SIZE
    refs = []

    for i in range(0, TEXT_SIZE, 4):
        off = text_file_start + i
        instr = read_u32be(data, off)
        if instr is None:
            continue

        opcode = (instr >> 26) & 0x3F
        if opcode != 0x0F:  # lui
            continue

        rt = (instr >> 16) & 0x1F
        imm_hi = instr & 0xFFFF

        if imm_hi not in hi_lo_map:
            continue

        # Check next 12 instructions for addiu/ori with same rt as source
        for j in range(1, 13):
            next_off = off + j * 4
            next_instr = read_u32be(data, next_off)
            if next_instr is None:
                break

            next_op = (next_instr >> 26) & 0x3F
            next_rs = (next_instr >> 21) & 0x1F
            next_imm = next_instr & 0xFFFF

            # addiu (0x09) or ori (0x0D) with rs=rt (using the lui result)
            if next_op in (0x09, 0x0D) and next_rs == rt:
                for (lo, sva, label, source) in hi_lo_map[imm_hi]:
                    if next_imm == lo:
                        ref_rva = off_to_rva(off)
                        refs.append((ref_rva, sva, label, source))
                break

            # If another lui overwrites the same register, stop
            if next_op == 0x0F and ((next_instr >> 16) & 0x1F) == rt:
                break

        if len(refs) % 2000 == 0 and len(refs) > 0:
            pct = (i * 100) // TEXT_SIZE
            print(f"  ... {len(refs)} refs found ({pct}% scanned)", file=sys.stderr)

    print(f"  Total xrefs found: {len(refs)}", file=sys.stderr)
    return refs


# ─── Step 3: Find function prologues ────────────────────────────────────────

def find_prologue(data, ref_rva):
    """Walk backward from ref_rva to find nearest addiu sp, sp, -N."""
    start_off = rva_to_off(ref_rva)
    text_start_off = FILE_OFF

    for back in range(0, MAX_PROLOGUE_SEARCH, 4):
        off = start_off - back
        if off < text_start_off:
            break
        instr = read_u32be(data, off)
        if instr is None:
            break
        hi16 = (instr >> 16) & 0xFFFF
        lo16 = instr & 0xFFFF
        if hi16 == PROLOGUE_ADDIU_SP and lo16 >= 0x8000:
            frame_size = 0x10000 - lo16
            return (off_to_rva(off), frame_size)

    return None


# ─── Step 4: Deduplicate and emit ───────────────────────────────────────────

def main():
    print(f"Loading {BINARY}...", file=sys.stderr)
    with open(BINARY, 'rb') as f:
        data = f.read()
    print(f"  {len(data):,} bytes loaded", file=sys.stderr)
    print(f"  Real code base: 0x{REAL_BASE:08X}", file=sys.stderr)
    print(f"  ELF VA base:    0x{ELF_VA_BASE:08X} (delta 0x{VA_DELTA:08X})", file=sys.stderr)

    # Step 1
    print("\n[Step 1] Extracting labeled strings...", file=sys.stderr)
    labeled = extract_labeled_strings(data)

    # Deduplicate: keep highest-priority label per string VA
    best = {}  # string_rva → (label, source, orig)
    for sva, label, source, orig in labeled:
        pri = SOURCE_PRIORITY.get(source, 1)
        if sva not in best or pri > SOURCE_PRIORITY.get(best[sva][1], 0):
            best[sva] = (label, source, orig)

    print(f"  Unique labeled strings: {len(best)}", file=sys.stderr)

    # Step 2
    print("\n[Step 2] Scanning .text for lui/addiu xrefs...", file=sys.stderr)
    refs = find_string_refs(data, [(sva, l, s, o) for sva, (l, s, o) in best.items()])

    # Step 3
    print("\n[Step 3] Walking back to function prologues...", file=sys.stderr)
    func_labels = {}  # prologue_rva → (label, source, frame_size, ref_count)
    no_prologue = 0

    for ref_rva, sva, label, source in refs:
        result = find_prologue(data, ref_rva)
        if result is None:
            no_prologue += 1
            continue

        prologue_rva, frame_size = result
        pri = SOURCE_PRIORITY.get(source, 1)

        if prologue_rva in func_labels:
            old_label, old_source, old_fs, old_cnt = func_labels[prologue_rva]
            old_pri = SOURCE_PRIORITY.get(old_source, 0)
            if pri > old_pri or (pri == old_pri and len(label) < len(old_label)):
                func_labels[prologue_rva] = (label, source, frame_size, old_cnt + 1)
            else:
                func_labels[prologue_rva] = (old_label, old_source, old_fs, old_cnt + 1)
        else:
            func_labels[prologue_rva] = (label, source, frame_size, 1)

    print(f"\n  Functions labeled:    {len(func_labels)}", file=sys.stderr)
    print(f"  No prologue found:   {no_prologue}", file=sys.stderr)

    # Source breakdown
    source_counts = defaultdict(int)
    for _, (_, source, _, _) in func_labels.items():
        source_counts[source] += 1
    print(f"\n  By source:", file=sys.stderr)
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"    {src:25s} {cnt:5d}", file=sys.stderr)

    # Step 4: Emit r2 script (using ELF VAs for r2)
    print(f"\n[Step 4] Writing r2 script to {OUTPUT_R2}...", file=sys.stderr)

    with open(OUTPUT_R2, 'w') as f:
        f.write(f"# ═══════════════════════════════════════════════════════════════════\n")
        f.write(f"# IOS Function Labels from Debug String Xrefs\n")
        f.write(f"# Binary: {os.path.basename(BINARY)}\n")
        f.write(f"# Functions labeled: {len(func_labels)}\n")
        f.write(f"# Real code base:   0x{REAL_BASE:08X}\n")
        f.write(f"# r2 load base:     0x{ELF_VA_BASE:08X}\n")
        f.write(f"# VA delta:         0x{VA_DELTA:08X}\n")
        f.write(f"# Generated by ios_string_labeler.py\n")
        f.write(f"# ═══════════════════════════════════════════════════════════════════\n\n")

        # Track label collisions
        used_labels = {}

        for rva in sorted(func_labels.keys()):
            label, source, frame_size, ref_count = func_labels[rva]
            elfva = rva_to_elfva(rva)

            # Sanitize label
            safe = re.sub(r'[^a-zA-Z0-9_]', '_', label)
            if safe[0].isdigit():
                safe = '_' + safe

            # Deduplicate label names
            if safe in used_labels:
                used_labels[safe] += 1
                safe = f"{safe}_{used_labels[safe]}"
            else:
                used_labels[safe] = 0

            f.write(f"af @ 0x{elfva:08x}\n")
            f.write(f"afn {safe} @ 0x{elfva:08x}\n")

        # Flag string locations
        f.write(f"\n# ── String flags ({len(best)} strings) ──\n")
        for sva in sorted(best.keys()):
            label, source, _ = best[sva]
            elfva = sva + VA_DELTA
            safe = re.sub(r'[^a-zA-Z0-9_]', '_', label)[:60]
            f.write(f"f str.{safe} @ 0x{elfva:08x}\n")

    # JSON manifest
    if OUTPUT_JSON:
        print(f"Writing JSON manifest to {OUTPUT_JSON}...", file=sys.stderr)
        manifest = {
            'binary': os.path.basename(BINARY),
            'real_base': f"0x{REAL_BASE:08x}",
            'elf_va_base': f"0x{ELF_VA_BASE:08x}",
            'va_delta': f"0x{VA_DELTA:08x}",
            'total_labeled': len(func_labels),
            'total_strings': len(best),
            'source_breakdown': dict(source_counts),
            'functions': {}
        }
        for rva in sorted(func_labels.keys()):
            label, source, frame_size, ref_count = func_labels[rva]
            manifest['functions'][f"0x{rva_to_elfva(rva):08x}"] = {
                'label': label,
                'source': source,
                'frame_size': frame_size,
                'real_va': f"0x{rva:08x}",
                'xref_count': ref_count,
            }
        with open(OUTPUT_JSON, 'w') as f:
            json.dump(manifest, f, indent=2)

    print(f"\nDone! Source {OUTPUT_R2} in an r2 session to apply labels.", file=sys.stderr)


if __name__ == '__main__':
    main()
