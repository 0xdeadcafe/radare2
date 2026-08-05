# Cisco IOS 12.x PPC32 Big-Endian Analysis Profile
# Platform: Cisco 1700 Series (c1700, c1710, c1711, c1720, c1721)
# CPU:      Motorola MPC860T (PowerPC 32-bit, big-endian)
# OS:       Cisco IOS (monolithic, cooperative scheduler)
# Tested:   c1700-tpgen+adventerprisek9-mz.PAGENT.4.2.2 (IOS 12.3 Experimental)
#           c1700-adventerprisek9-mz.124-15.T10.bin (IOS 12.4(15)T10)
#
# ELF notes:
#   - Machine type 0x33 (51) = "Stanford MIPS-X" — Cisco's legacy marker
#     The actual ISA is PowerPC 32-bit big-endian (MPC860T)
#   - Entry point: 0x80008000 (KSEG0-like, physical = 0x00008000)
#   - Named sections present: .text, .rodata, .sdata2, .data, .sdata, .sbss, .bss
#   - Stripped: zero symbols
#   - Statically linked: no dynamic section, no PLT/GOT
#
# CRITICAL: file/readelf reports "Stanford MIPS-X" but the ISA is PowerPC.
# r2 must be opened with: -a ppc -b 32 -e cfg.bigendian=true
#
# Blob format (outer -mz wrapper):
#   [ELF header + decompression stub]  ~14KB  (section [1], PPC code)
#   [CW_VERSION / CW_FEATURE tags]     ~2KB   (section [2], ASCII metadata)
#   [FEEDFACE magic + PKZIP container]  bulk   (section [6], compressed IOS image)
#   FEEDFACE at file offset 0x467c, PK\x03\x04 follows
#   Decompress: zipfile.ZipFile(data[pk_offset:]).read(...)
#
# Memory map (from C1700-TP.BIN, PAGENT 12.3 Experimental):
#   .text       0x80008000 - 0x8237831B  (~37 MB, WAX)
#   .rodata     0x8238031C - 0x8344FB5F  (~17 MB, A)
#   .sdata2     0x8344FB60 - 0x8344FB5F  (0 bytes, A)
#   .data       0x8344FB60 - 0x8396ED1B  (~5 MB, WA)
#   .sdata      0x8396ED1C - 0x8396F023  (308 bytes, WA)
#   .sbss       0x8396F028 - 0x839753F7  (~25 KB, WA)
#   .bss        0x839753F8 - 0x83CEE5EB  (~3.5 MB, WA)
#
# Usage:
#   r2 -a ppc -b 32 -e cfg.bigendian=true -i cisco-ios-ppc32.r2 C1700-TP.BIN
#
# r2_open flags: ["-a", "ppc", "-b", "32", "-e", "cfg.bigendian=true"]
# init_cmds:    ". ~/.local/share/radare2/profiles/cisco-ios-ppc32.r2"

# =============================================================================
# Architecture
# =============================================================================
e asm.arch=ppc
e asm.bits=32
e cfg.bigendian=true

# =============================================================================
# Analysis settings — tuned for IOS monolithic PPC image
# =============================================================================
e anal.hasnext=true
e anal.jmp.tbl=true
e anal.jmp.after=true
e anal.strings=true
e anal.depth=128
e anal.timeout=600
e anal.imports=false
e anal.gp=0
e anal.maxreflines=32768

# =============================================================================
# IOS Memory Map Annotations (PAGENT 12.3 / c1700)
# =============================================================================
f map.text    = 0x80008000
f map.rodata  = 0x8238031C
f map.data    = 0x8344FB60
f map.sdata   = 0x8396ED1C
f map.sbss    = 0x8396F028
f map.bss     = 0x839753F8

# =============================================================================
# PPC function prologue signatures
#
# Typical PPC IOS function prologue:
#   stwu  r1, -N(r1)       (94 21 XX XX — allocate stack frame)
#   mflr  r0               (7C 08 02 A6 — save link register)
#   stw   r0, M(r1)        (90 01 XX XX — save LR to stack)
#   stmw  rN, K(r1)        (BF XX XX XX — save multiple regs)
#
# Epilogue:
#   lwz   r0, M(r1)        (80 01 XX XX — restore LR)
#   mtlr  r0               (7C 08 03 A6)
#   addi  r1, r1, N        (38 21 XX XX — deallocate frame)
#   blr                    (4E 80 00 20 — return)
#
# =============================================================================

# =============================================================================
# IOS Cooperative Scheduler (same architecture as C1900)
# Process names for c1700:
#   "IP Input", "Net Input", "ARP Input", "CDP Protocol"
#   "SNMP ENGINE", "HTTP CORE", "TCP Protocols", "VTY Background"
#   "Pagent" (PAGENT builds only)
# =============================================================================

# =============================================================================
# c1700-Specific Hardware
# CPU: MPC860T (PowerPC core + Communication Processor Module)
# Source paths found: ../src-m860-c1700/, ../src-m860-les/
# Key files:
#   c1700.c — platform init
#   platform_c1700.c — platform-specific functions
#   pquicc_lib.c — MPC860 QUICC library
#   if_c1700_mainboard.c — mainboard interface driver
#   c1700_voice_router_tdm.c — voice TDM support
#   c1700_clock_parser.c — clock configuration
# =============================================================================

# =============================================================================
# PAGENT-Specific Features (debug/test build only)
#
# PAGENT = Packet Agent — Cisco internal test framework
# Key strings:
#   "Welcome to Pagent V%d.%d!"
#   "Pagent commands:"
#   "http://wwwin-pagent.cisco.com" (internal Cisco URL)
#   "Pagent is Cisco proprietary technology"
#
# PAGENT adds:
#   - Packet generator (tpgen): create/send arbitrary packets
#   - Packet capture: capture and dump packets
#   - Convergence testing: measure routing convergence time
#   - Traffic generation: sustained load generation
#   - Debug CLI commands not in production builds
#
# Attack surface: PAGENT CLI commands accept raw packet data
# without authentication when accessed via console or VTY.
# =============================================================================

# =============================================================================
# Known Vulnerability Surfaces in IOS 12.x c1700
#
# Priority 1 (Remote, pre-auth):
#   - HTTP server: "/level/XX/exec/" auth bypass (CVE-2001-0537)
#   - SNMP: default communities "public"/"private"/"ILMI"
#   - Telnet: cleartext management (always enabled by default)
#   - ISAKMP/IKE: IPsec key exchange (k9 feature sets)
#   - CDP: Layer 2, adjacent only
#
# Priority 2 (Remote, post-auth):
#   - CLI command injection
#   - TFTP file transfer
#   - RADIUS/TACACS+
#   - BGP/OSPF/EIGRP parsers
#
# Note: IOS 12.0-12.2 images lack many security fixes present in 12.4+
# =============================================================================

# =============================================================================
# Zignature settings
# =============================================================================
e zign.graph=true
e zign.refs=true
e zign.minscore=0.70
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4

# Load PPC IOS zignatures when available
# Note: C1700-TP.BIN is a stripped monolithic binary (no ELF symbols).
# All 9402 zsig entries are unnamed fcn.* byte-patterns — useful for
# cross-version function identification but not for direct name resolution.
# Run `z/` then manually rename matching functions.
zo cisco-ios/ppc32/ios-12.3-pagent-c1700.zsig

# =============================================================================
# Display preferences
# =============================================================================
e asm.describe=true
e asm.comments=true
e asm.cmt.col=55
e asm.xrefs=true
e asm.size=true
e asm.bytes=true
e asm.nbytes=4
e str.limit=256

# =============================================================================
# Workflow (for c1700 PPC images):
#
# 1. Decompress the -mz wrapper first:
#      python3 -c "
#      import zipfile, io
#      data = open('image.bin','rb').read()
#      pk = data.find(b'PK\x03\x04', 0x4000)
#      zf = zipfile.ZipFile(io.BytesIO(data[pk:]))
#      open('C1700-XX.BIN','wb').write(zf.read(zf.infolist()[0].filename))
#      "
#
# 2. Open with correct arch:
#      r2 -a ppc -b 32 -e cfg.bigendian=true C1700-XX.BIN
#
# 3. DO NOT run 'aaa' on 57MB image — use targeted analysis:
#      iz~<pattern>          # find string
#      axt <string_addr>     # find referencing function
#      af @ <func_addr>      # analyze just that function
#      pdg                   # decompile
#
# 4. String-based labeling:
#      python3 ios_string_labeler.py C1700-XX.BIN /tmp/labels.r2 /tmp/labels.json
#      . /tmp/labels.r2
# =============================================================================
