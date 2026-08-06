# libc/TODO.md — Missing zsig coverage tracker
# Last updated: 2026-08-06

# Priority 1 — OPEN (needs external resource)
# ─────────────────────────────────────────────

# macOS zsigs (x64 + arm64)
#   Needed for: macOS Mach-O analysis (profiles created, zsigs pending)
#   Generate:   When macOS SDK available — extract from /usr/lib/libSystem.dylib
#               or use Homebrew dylibs on an Apple host
#   Status:     BLOCKED — requires Apple host or macOS SDK license

# Priority 2 — RESOLVED
# ──────────────────────

# debian/armhf full set (23 zsigs)    — DONE 2026-08-06 (Batch 2)
# debian/i386  full set (22 zsigs)    — DONE 2026-08-06 (Batch 2)
# debian/arm64 libcrypto-static       — DONE 2026-08-06 (Batch 2)
# debian/arm64 libprotobuf            — DONE 2026-08-06 (Batch 2)
# freertos CM0/CM3/CM4/CM7            — DONE 2026-08-06 (Batch 3b, generate-freertos-zsig.py)
# uclibc-ng arm64                     — DONE 2026-08-06 (Batch 3c, generate-uclibc-arm64-zsig.py)
# glibc-arm32.r2                      — DONE (zsig: zigns/glibc/armhf/glibc-libc.zsig)
# uclibc-mips64.r2                    — DONE (profile created 2026-05-14)
# uclibc-mips64-n32.r2                — DONE (profile created 2026-05-14)
# musl-x86.r2                         — DONE (profile created 2026-05-14)
# linux-glibc-arm32.r2                — DONE (standalone top-level profile, 2026-08-01)
# linux-musl-arm32.r2                 — DONE (standalone top-level profile, 2026-08-01)
# linux-musl-armv7.r2                 — DONE (standalone top-level profile, 2026-08-01)
# linux-glibc-x64.r2                  — DONE (top-level profile, 2026-08-05)
# linux-glibc-arm64.r2                — DONE (top-level profile, 2026-08-05)
# freebsd-x64.r2                      — DONE (new profile, 2026-08-05; now loads full amd64 set)
# macos-x64.r2 / macos-arm64.r2       — DONE profiles (2026-08-05; zsigs TODO above)
# uclibc-arm32.r2                     — DONE (zsig: zigns/uclibc/arm32/uclibc-libc.zsig,
#                                              Bootlin armv5-eabi 2024.02, 3269 sigs, 2026-08-05)
# linux-uclibc-arm32.r2 top-level     — DONE (2026-08-05)
# linux-glibc-x86.r2 + libc/glibc-x86.r2 — DONE (Batch 1, 2026-08-06)
