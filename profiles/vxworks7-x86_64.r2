# VxWorks 7 x86-64 Analysis Profile
# Source: wrsdk-vxworks7-qemu-1.16.1 (VxWorks OS 25.09, LLVM 18.1.8.1)
# BSP:    itl_generic_3_0_0_4 (Intel/AMD x86-64, QEMU target)
#
# Covers:
#   - Full kernel image (vxWorks ELF, statically linked, ~500 MB with debug)
#   - RTP (Real-Time Process) user-space ELFs (.vxe)
#   - DKM (Downloadable Kernel Module) relocatable objects (.out)
#
# Usage:
#   r2 -i profiles/vxworks7-x86_64.r2 vxWorks
#   r2 -i profiles/vxworks7-x86_64.r2 app.vxe
#   Or from r2 prompt: . profiles/vxworks7-x86_64.r2

# =============================================================================
# Architecture
# =============================================================================
e asm.arch=x86
e asm.bits=64
e cfg.bigendian=false

# =============================================================================
# VxWorks kernel memory map (itl_generic / QEMU Intel BSP)
#
#   .text.locore    0x00408000  locore trampoline + SMP init (LE user-space range)
#   .data.locore    0x00409000  locore data (page tables, GDT, IDT setup)
#   .text (kernel)  0xffffffff8040e000  main kernel .text (negative canonical)
#   .data (kernel)  0xffffffff9ec56000
#   .bss  (kernel)  0xffffffff9edc6a00
#
# NOTE: When loading a stripped kernel dump (no ELF headers), map manually:
#   om.add 0x408000 0x5000 rwx locore
#   om.add 0xffffffff8040e000 <size> rwx ktext
# =============================================================================

# Demangle C++ symbols (VxWorks 7 uses Itanium ABI via LLVM)
e bin.demangle=true
e bin.demanglecmd=true

# =============================================================================
# Analysis settings
# =============================================================================
# hasnext: continue analysis past function boundaries (VxWorks tail-call heavy)
e anal.hasnext=true
# Jump table analysis — VxWorks switch dispatch uses indirect jmp tables
e anal.jmp.tbl=true
# Strings inline — VxWorks error strings often inlined via MOV imm
e anal.strings=true
# RTTI — VxWorks 7 C++ uses standard Itanium ABI typeinfo
e anal.cpp.abi=itanium
# Don't limit recursion depth — kernel functions chain deeply
e anal.depth=64

# =============================================================================
# Zignature autoloading
# =============================================================================
e zign.graph=true
e zign.refs=true
# Minimum match threshold — raise for noisy kernels, lower for sparse RTP
e zign.minscore=0.75
# Lower matching thresholds — default mincc=10 kills simple functions (1-3 BBs)
e zign.mincc=1
e zign.minsz=4

# Load VxWorks 7 x86-64 zignatures from this repo
# Adjust path if installed elsewhere
# Generated from wrsdk-vxworks7-qemu-1.16.1 (VxWorks OS 25.09, LLVM 18.1.8.1)
zo vxworks/x86_64/vxworks7-libc.zsig
zo vxworks/x86_64/vxworks7-libssl.zsig
zo vxworks/x86_64/vxworks7-libcrypto.zsig
zo vxworks/x86_64/vxworks7-libcurl.zsig
zo vxworks/x86_64/vxworks7-libdl.zsig
zo vxworks/x86_64/vxworks7-libunix.zsig
zo vxworks/x86_64/vxworks7-libnet.zsig
zo vxworks/x86_64/vxworks7-libxml.zsig
zo vxworks/x86_64/vxworks7-libz.zsig
zo vxworks/x86_64/vxworks7-libcjson.zsig
zo vxworks/x86_64/vxworks7-libmosquitto.zsig
zo vxworks/x86_64/vxworks7-libomp.zsig
zo vxworks/x86_64/vxworks7-libbz2.zsig
zo vxworks/x86_64/vxworks7-libmbedtls_hash.zsig
zo vxworks/x86_64/vxworks7-libuuid.zsig
zo vxworks/x86_64/vxworks7-libcplus-krnl.zsig
zo vxworks/x86_64/vxworks7-sqlite3.zsig

# Type definitions
e dir.types=~/.local/share/radare2/types
to libc/functions.h
to libc/socket.h
to libc/fcntl.h
to libc/signal.h
to vxworks/vxworks.h
to openssl/ssl.h
to openssl/crypto.h
to zlib/zlib.h

# VxWorks MIPS/ARM zsig coverage: requires Wind River SDK variants.
# To generate for MIPS32-BE:
#   python3 tool/generate-vxworks-zsig.py --arch mips32be \
#       --sdk /path/to/wrsdk-vxworks7-mips -o zigns/vxworks/mips32be/
# To generate for ARM32:
#   python3 tool/generate-vxworks-zsig.py --arch arm32 \
#       --sdk /path/to/wrsdk-vxworks7-arm -o zigns/vxworks/arm32/
# Profile stubs: create vxworks7-mips32be.r2 and vxworks7-arm32.r2 once zsigs exist.

# =============================================================================
# VxWorks RTOS primitive annotations
#
# Known VxWorks 7 x86-64 kernel entrypoints / syscall vectors.
# These are BSP-specific; adjust addresses for non-QEMU targets.
# For the itl_generic BSP kernel (wrsdk-vxworks7-qemu-1.16.1):
#
#   - Locore entry:     0x408000  (SMP init trampoline, ljmp to kernel)
#   - Kernel _start:    0xffffffff8040e000 (ELF e_entry after locore)
#
# Run 'aaa' after loading to auto-detect via zignatures, then:
#   z/  — apply loaded sigs to all functions
#   axt sym.taskSpawn~[0]  — find all taskSpawn callers
#   axt sym.semTake~[0]    — find semaphore acquisition sites
# =============================================================================

# =============================================================================
# Display preferences
# =============================================================================
e asm.describe=true
e asm.comments=true
e asm.cmt.col=60
# Show xrefs inline — critical for VxWorks task/ISR dispatch chains
e asm.xrefs=true
# Show function size in listings
e asm.size=true

# =============================================================================
# Workflow reminders (comments only, not executed)
#
# 1. Initial triage:
#      rabin2 -I vxWorks
#      rabin2 -z vxWorks | grep -i "vxworks\|wind\|copyright"
#
# 2. Full analysis (kernel is large — expect ~10 min with debug info):
#      aaa
#
# 3. Apply signatures:
#      z/
#
# 4. VxWorks-specific entry points:
#      s sym.usrAppInit   # application init hook (RTP / linked-in apps)
#      s sym.usrRoot      # root task entry  (kernel)
#      s sym.sysStart     # BSP hardware init
#
# 5. Find RTOS primitives by xref:
#      axt sym.taskSpawn
#      axt sym.semBCreate
#      axt sym.msgQCreate
#
# 6. Check for hard-coded keys / certs near crypto xrefs:
#      /x 2d2d2d2d2d424547494e     # "-----BEGIN"
#      axt sym.sslCtxNew
# =============================================================================
