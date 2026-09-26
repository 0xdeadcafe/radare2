# Cisco IOS 15.x MIPS32 Big-Endian Analysis Profile
# Platform: Cisco 1900 Series ISR (Integrated Services Router)
# CPU:      Cavium Octeon (MIPS64-compatible, IOS runs in 32-bit mode)
# OS:       Cisco IOS (monolithic, no Linux/VxWorks — custom cooperative scheduler)
# Tested:   c1900-universalk9-mz.SPA 15.0(1)M through 15.2(1)T
#
# ELF notes:
#   - Machine type 0xC0 (192) = "CloudShield" — Cisco's custom ELF e_machine
#     r2 / readelf call it "unknown arch 0xc0" but the ISA is MIPS32-BE
#   - Entry point: 0x81000000 (KSEG0 cached unmapped region)
#
# CRITICAL ADDRESSING NOTE (discovered 2026-04-28):
#   The ELF VA is 0x81000000 (KSEG0), but the code was COMPILED for base
#   0x21000000. All lui/addiu address pairs, jal targets, and data references
#   use 0x21xxxxxx-0x27xxxxxx addresses internally. r2 loads at 0x81000000
#   per the ELF header, so there is a constant delta of 0x60000000:
#     real_compiled_addr = r2_addr - 0x60000000
#     r2_addr = real_compiled_addr + 0x60000000
#   This affects manual address calculations but NOT r2 analysis (r2 works
#   with the ELF VAs and resolves references correctly).
#   - Single LOAD segment: 0x81000000, RWE (text+data+bss combined)
#   - Stripped: zero symbols, all section names blank
#   - Statically linked: no dynamic section, no PLT/GOT
#
# Memory map (from ELF program headers, 15.2(1)T):
#   .text       0x81000000 - 0x84F57FFF  (~63 MB, WAX)
#   .rodata     0x84F58000 - 0x86981BFF  (~26 MB, A)
#   .rodata2    0x86981C00 - 0x86981C6F  (112 bytes, A)
#   .data       0x86981C70 - 0x877CD3DF  (~14 MB, WA)
#   .data2      0x877CD3E0 - 0x877CD3FF  (32 bytes, WA)
#   .data3      0x877CD400 - 0x877CDB7F  (~2 KB, WAp — processor-specific)
#   .bss        0x877CDB80 - 0x877D3FBF  (~26 KB, WAp)
#   .bss2       0x877D3FC0 - 0x8836FFxx  (~12 MB, WA — extends to MemSiz)
#   debug/strtab 0x80000000 (not loaded — offset 0x67cdbe0, ~5.8 MB)
#
# Usage (IMPORTANT: must specify -a mips at open time to override CloudShield arch):
#   r2 -a mips -b 32 -e cfg.bigendian=true -i ~/.local/share/radare2/profiles/cisco-ios-mips32.r2 C1900-UN.BIN
#   Or from r2 prompt (only works if arch was set at open time):
#     . ~/.local/share/radare2/profiles/cisco-ios-mips32.r2
#
# r2_open flags: ["-a", "mips", "-b", "32", "-e", "cfg.bigendian=true"]
# init_cmds:    ". ~/.local/share/radare2/profiles/cisco-ios-mips32.r2"

# =============================================================================
# Architecture
# =============================================================================
e asm.arch=mips
e asm.bits=32
e cfg.bigendian=true

# =============================================================================
# Analysis settings — tuned for IOS monolithic image
# =============================================================================

# IOS is statically linked — all functions are local, no PLT resolution
e anal.hasnext=true

# MIPS jump table analysis (IOS CLI parser uses massive switch dispatch)
e anal.jmp.tbl=true
e anal.jmp.after=true

# String analysis — IOS embeds format strings and error messages inline
e anal.strings=true

# Deep recursion — IOS function chains are very deep
# (parser → subsystem → protocol → buffer management → I/O)
e anal.depth=128

# Timeout per function (seconds) — some IOS functions are enormous
e anal.timeout=600

# Don't try to resolve imports (statically linked, no dynamic section)
e anal.imports=false

# MIPS GP register — IOS doesn't use a global pointer in the traditional sense
# (monolithic image, no shared libs), but some subsystems use $gp-relative addressing.
# Set to 0 and let r2 detect per-function if needed.
e anal.gp=0

# Increase analysis limits for large binary (~110 MB .text)
e anal.maxreflines=32768

# =============================================================================
# IOS Memory Map Annotations
# =============================================================================
# Text segment starts at KSEG0 0x81000000
# KSEG0 = physical 0x01000000 | 0x80000000 (cached, unmapped)
# KSEG1 = physical 0x01000000 | 0xA0000000 (uncached, unmapped — MMIO)

# Flag the major regions for navigation
f map.text    = 0x81000000
f map.rodata  = 0x84F58000
f map.data    = 0x86981C70
f map.bss     = 0x877CDB80

# =============================================================================
# IOS-specific function signatures
#
# IOS has no symbol table, but known function prologues and string patterns
# allow identification of key subsystems.
#
# Typical MIPS32 IOS function prologue:
#   addiu sp, sp, -N     (27BD XXXX — allocate stack frame)
#   sw ra, M(sp)         (AFBF XXXX — save return address)
#   sw s0-s7, ...        (AFB0-AFB7 — save callee-saved regs)
#
# =============================================================================

# =============================================================================
# IOS Process / Scheduler Primitives
#
# IOS uses a cooperative (non-preemptive) scheduler. Key functions:
#   process_create()     — creates a new IOS process (like a coroutine)
#   process_sleep_for()  — yield with timer
#   process_suspend()    — suspend a process
#   process_set_name()   — set process name (string xref target)
#
# Find scheduler: search for process name strings:
#   / *Init*
#   / *Dead*
#   / *Sched*
#   / Check heaps
#   / Pool Manager
#   / Net Input
#   / ARP Input
#   / IP Input
#   Then xref backwards to find process_create() callers
#
# =============================================================================

# =============================================================================
# IOS CLI Parser
#
# IOS CLI uses a tree-structured command parser. Key patterns:
#   - Command token strings: "show", "debug", "ip", "interface", etc.
#   - Parser node structures contain: token string ptr, help string ptr,
#     handler function ptr, next/child node ptrs
#   - The parser dispatch function is identifiable by the string:
#     "% Invalid input detected at '^' marker"
#     "% Ambiguous command"
#     "% Incomplete command"
#
# Vulnerability hunting: find parser nodes that accept unchecked user input
# and pass it to buffer operations (strcpy, sprintf, memcpy without bounds).
#
# =============================================================================

# =============================================================================
# IOS Heap (Memory Pool) Management
#
# IOS uses a custom heap allocator with "memory pools":
#   - "Processor Pool" — main heap for process memory
#   - "I/O Pool" — packet buffers
#   - malloc() equivalent: internal, strings "Malloc fail" on OOM
#   - Each chunk has a header with magic / redzone markers
#   - Heap corruption = known IOS exploit primitive
#
# Key functions to find (by string xref):
#   malloc()    → "MALLOC_FAIL" string
#   free()      → "free_check" string
#   chunk validation → "DEADbeef" / chunk header magic
#
# =============================================================================

# =============================================================================
# Known Vulnerability Surfaces in IOS 15.x
#
# Priority 1 (Remote, pre-auth):
#   - SNMP (community strings: "public", "private", "ILMI" found in binary)
#   - HTTP server (ip http server / ip http secure-server)
#   - Smart Install (SMI) protocol — CVE-2018-0171 era
#   - IKE/ISAKMP — IPsec VPN key exchange
#   - SIP (Session Initiation Protocol) — VoIP
#   - H.323 — VoIP
#
# Priority 2 (Remote, post-auth or complex):
#   - BGP/OSPF/EIGRP (routing protocol parsers)
#   - TFTP/FTP file transfer
#   - RADIUS/TACACS+ AAA
#   - CDP (Cisco Discovery Protocol) — Layer 2, adjacent only
#
# Priority 3 (Local / post-exploit):
#   - CLI command injection (privilege escalation)
#   - ROMMON escape
#   - Heap overflow → code execution
#
# Search strategy:
#   1. Find protocol handler registration (strings: "snmpd", "HTTP",
#      "Smart Install", "SIP", "H.323", etc.)
#   2. Xref back to find the packet receive / parse function
#   3. Trace data flow from network input to buffer operations
#
# =============================================================================

# =============================================================================
# Zignature autoloading
# =============================================================================
e zign.graph=true
e zign.refs=true
e zign.minscore=0.70
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4

# Load Cisco IOS MIPS32 zignatures
# Generated from IOS 15.2(1)T C1900-UN.BIN: 4,874 NAMED function signatures
# Covers: all debug-string-labeled functions (subsystem, VIEW_ROOT, OpenSSL, etc.)
zo cisco-ios/mips32/ios-15.2.1T-c1900.zsig

# =============================================================================
# String-based function labeling (Method 2 — PREFERRED for new binaries)
# =============================================================================
# The zsig above works for re-opening the SAME 15.2(1)T binary.
# For OTHER IOS versions or fresh analysis, use the string labeler instead:
#
#   # Step 1: Generate version-specific labels (< 10 seconds on any IOS image)
#   python3 ~/.local/share/radare2/zigns/cisco-ios/mips32/ios_string_labeler.py \
#       <binary_path> /tmp/ios_labels.r2 /tmp/ios_labels.json
#
#   # Step 2: Source the labels in r2
#   . /tmp/ios_labels.r2
#
# This labels 3,000-5,200+ functions depending on IOS version by:
#   - VIEW_ROOT source paths (assert/debug strings leak .c filenames)
#   - funcname() debug prints (functions that print their own name)
#   - Subsystem prefix strings (smi_*, ikev2_*, crypto_*, etc.)
#   - OpenSSL API names (error callback registration strings)
#   - Debug messages with function names ("SUBSYS: funcname ...")
#
# Cross-version stats (15 images, 15.0(1)M through 15.2(1)T):
#   Total unique labels: 3,597
#   Core (all versions):  1,241
#   Stable (>=10 vers):   2,021
#   Per-version range:    2,405 - 5,258
#
# Pre-built label scripts available:
#   ios-15.0.1M-labels.r2   — oldest version in corpus
#   ios-15.1.3T1-labels.r2  — first version with Smart Install (SMI)
#   ios-15.2.1T-labels.r2   — newest version in corpus
#   ios_core_labels.r2      — stable labels across all versions (for 15.2.1T addrs)
#
# KEY DISCOVERY: Smart Install (CVE-2018-0171 surface) first appears in 15.1(3)T1.
# All 15.0.x and 15.1(1-2)T images have ZERO smi_ functions.
#
# To generate zsigs from labeled functions:
#   zg                  (auto-generate from all analyzed functions)
#   zos cisco-ios/mips32/ios-<version>.zsig

# =============================================================================
# Display preferences
# =============================================================================
e asm.describe=true
e asm.comments=true
e asm.cmt.col=55
e asm.xrefs=true
e asm.size=true
# Show bytes — useful for MIPS instruction pattern matching
e asm.bytes=true
e asm.nbytes=4
# Don't truncate long strings
e str.limit=256

# =============================================================================
# Workflow reminders (comments only, not executed)
#
# 1. Initial triage (fast — no full analysis):
#      rabin2 -I C1900-UN.BIN
#      rabin2 -z C1900-UN.BIN | head -50
#
# 2. Targeted analysis (DON'T run 'aaa' on 110MB image — will take hours):
#      # Instead, find target functions by string xref:
#      / Smart Install
#      axt hit0_0          # find referencing function
#      af @ <func_addr>    # analyze just that function
#      pdg                 # decompile
#
# 3. Find protocol handlers by string search:
#      /j snmp_input       # SNMP packet handler
#      /j http_process     # HTTP server
#      /j smi_             # Smart Install
#      /j isakmp_          # IKE/ISAKMP
#
# 4. SNMP attack surface:
#      / public            # default community strings
#      / private
#      / ILMI
#      / community         # community string handling code
#      # Then trace the SNMP PDU parser for buffer overflows
#
# 5. IOS heap exploitation:
#      / Processor Pool    # find heap allocator
#      / chunk_            # chunk management functions
#      / DEADbeef          # heap metadata magic
#
# 6. CLI parser attack surface:
#      / Invalid input detected
#      / Incomplete command
#      # Xref back to find the main CLI dispatch
#      # Look for handlers that pass user input unsanitized
#
# 7. Diffing between versions:
#      radiff2 -g C1900-UN_v150.BIN C1900-UN_v152.BIN
#      # Patches between versions reveal fixed vulnerabilities
#
# =============================================================================
