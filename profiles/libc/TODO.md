# libc/TODO.md — Missing zsig coverage tracker
# Last tested: 2026-08-01

# Priority 1 — HIGH (unblocks active targets)
# ──────────────────────────────────────────

# uclibc-arm32.r2
#   Needed for: Supermicro BMC (ARM926EJ-S, uClibc 0.9.33)
#   Profile:    CREATED (stub, zo line commented out)
#   Missing:    uclibc/arm32/uclibc-libc.zsig
#   Generate:   Extract libuClibc.so from Supermicro BMC rootfs, then:
#                 mkdir -p zigns/uclibc/arm32/
#                 rasign2 -A -o zigns/uclibc/arm32/uclibc-libc.zsig /path/to/libuClibc.so

# Priority 2 — RESOLVED
# ─────────────────────
# glibc-arm32.r2      — DONE (zsig: zigns/glibc/armhf/glibc-libc.zsig, profile functional)
# uclibc-mips64.r2    — DONE (profile created 2026-05-14)
# uclibc-mips64-n32.r2 — DONE (profile created 2026-05-14)
# musl-x86.r2         — DONE (profile created 2026-05-14)
# linux-glibc-arm32.r2 — DONE (standalone top-level profile, 2026-08-01)
# linux-musl-arm32.r2  — DONE (standalone top-level profile, 2026-08-01)
# linux-musl-armv7.r2  — DONE (standalone top-level profile, 2026-08-01)
