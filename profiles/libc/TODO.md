# libc/TODO.md — Missing zsig coverage tracker
# Last updated: 2026-08-05

# Priority 1 — HIGH (unblocks active targets)
# ──────────────────────────────────────────

# macos zsigs (x64 + arm64)
#   Needed for: macOS Mach-O analysis (profiles created, zsigs pending)
#   Generate:   When macOS SDK available — extract from /usr/lib/libSystem.dylib
#               or use Homebrew dylibs on an Apple host

# Priority 2 — RESOLVED
# ─────────────────────
# glibc-arm32.r2          — DONE (zsig: zigns/glibc/armhf/glibc-libc.zsig)
# uclibc-mips64.r2        — DONE (profile created 2026-05-14)
# uclibc-mips64-n32.r2    — DONE (profile created 2026-05-14)
# musl-x86.r2             — DONE (profile created 2026-05-14)
# linux-glibc-arm32.r2    — DONE (standalone top-level profile, 2026-08-01)
# linux-musl-arm32.r2     — DONE (standalone top-level profile, 2026-08-01)
# linux-musl-armv7.r2     — DONE (standalone top-level profile, 2026-08-01)
# linux-glibc-x64.r2      — DONE (top-level profile, 2026-08-05)
# linux-glibc-arm64.r2    — DONE (top-level profile, 2026-08-05)
# freebsd-x64.r2          — DONE (new profile, 2026-08-05)
# macos-x64.r2            — DONE (new profile, 2026-08-05; zsigs TODO)
# macos-arm64.r2          — DONE (new profile, 2026-08-05; zsigs TODO)
# uclibc-arm32.r2         — DONE (zsig: zigns/uclibc/arm32/uclibc-libc.zsig,
#                                  Bootlin armv5-eabi 2024.02, 3269 sigs, 2026-08-05)
#                           Profile: profiles/libc/uclibc-arm32.r2
#                           Loaded by: supermicro-bmc-arm.r2
