/**
 * tt_cshell.h — Cobham / Thrane & Thrane (Viasat) embedded platform type definitions
 *
 * Covers: acu_ctl, acu_vmu, suu, cbus_server — Cobham TT-7xxx / SAILOR GX family
 *
 * Platform: Viasat SAILOR TT-7xxx ACU (Explorer 3075/5075/6075/7100GX,
 *            SAILOR 60GX/100GX/600/900/1000 VSAT GX)
 * Arch:     ARM32 LE Linux (uClibc/musl); main services are ARM Thumb-2
 * Libc:     varies by firmware version — uClibc (v1.61-1.64), musl-like (v1.66+)
 * Mitigations: NONE across all versions — no canary, no NX, no PIE, no RELRO
 *
 * Basis:
 *   - acu_ctl r2ghidra pdg + strings analysis (binary 99fda815, fw 1.64B016, 2026-04-25)
 *   - acu_vmu r2ghidra pdg (binary 539e9d11, SAILOR 60GX fw 1.64B016, 2026-04-25)
 *   - acu_vmu r2ghidra pdg (binary cab13b2a, Explorer GX fw 1.61b010, 2026-04-24)
 *   - suu r2ghidra pdg + readelf analysis (binary 069d7d9a, fw 1.66-9, 2026-04-24)
 *   - vault/Findings/CMD_INJECTION_99fda815_1.md
 *   - vault/Findings/CMD_INJECTION_539e9d11_1.md
 *   - vault/Findings/STACK_OVERFLOW_cab13b2a_1.md
 *   - vault/Findings/UNSIGNED_FW_069d7d9a_suu_tiif.md
 *   - vault/Findings/VULN_MATRIX_tt7xxx_cross_version.md
 *   - vault/Patterns/Cobham_tt_cshell_System_Exec.md
 *   - vault/Patterns/SUID_Firmware_CRC32_Only.md
 *
 * Load in r2:   to cobham/tt_cshell.h
 * Future use:   profiles/cobham-sailor-arm.r2 (profile not yet written)
 *
 * Extend this file and run corpus_commit.py after new analysis sessions.
 */

#ifndef COBHAM_TT_CSHELL_H
#define COBHAM_TT_CSHELL_H

#include <stdint.h>
#include <stddef.h>

/* ══════════════════════════════════════════════════════════════════════════════
 * SECTION 1: tt_cshell Debug Shell Framework
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * The "tt_cshell" framework is Thrane & Thrane's internal embedded CLI, used in
 * acu_ctl (port 2323) and acu_vmu (port 2327) for local debug access. The shell
 * is reachable via a telnetd listener bound to tcp*127.0.0.1*PORT (libfdloop).
 *
 * The dispatcher at fcn.0003eeec in acu_ctl (0x3eeec) reads one character, maps
 * it through a switch table (cases 'a' through 's' = 0x61..0x73), and calls the
 * corresponding handler. Case 18 ('s') calls system(rest_of_input) directly.
 *
 * Seen in:    acu_ctl (2323), acu_vmu (2327, 2330), confirmed in all 5 fw versions
 * Reference:  vault/Patterns/Cobham_tt_cshell_System_Exec.md
 */

/* Shell command character assignments (switch table in fcn.0003eeec) */
#define TT_CSHELL_CMD_FIRST     0x61  /* 'a' — first valid command character */
#define TT_CSHELL_CMD_LAST      0x73  /* 's' — last valid command character (SYSTEM) */
#define TT_CSHELL_CMD_SYSTEM    0x73  /* 's' = case 18 → system(rest_of_input) */
#define TT_CSHELL_CMD_COUNT     19    /* cases 0..18 ('a'..'s') */

/* tt_cshell command dispatch entry (switch table entry, 8 bytes) */
typedef struct tt_cshell_cmd {
    char     cmd_char;           /* 0x00 — single command character ('a'..'s') */
    uint8_t  _pad[3];            /* 0x01 — alignment */
    uint32_t handler_offset;     /* 0x04 — offset from table base to case block */
} tt_cshell_cmd_t;

/* tt_readline state block (arg1 to tt_readline_char @ 0x5cd74 in acu_ctl)
 *
 * A stack overflow exists in tt_readline_char when tab-completion is triggered
 * (key == 9): strcpy(arg1+0x1c, current_line) + strcat(arg1+0x1c, completion)
 * with no bounds check on the 0x1c-offset destination buffer.
 */
typedef struct tt_readline_state {
    uint32_t  fd;               /* 0x00 — file descriptor for terminal I/O */
    uint32_t  history_ptr;      /* 0x04 — pointer to history buffer */
    uint32_t  tab_callback;     /* 0x08 — function pointer: tab_complete(fd, buf) */
    uint32_t  tab_arg;          /* 0x0c — opaque arg passed to tab_callback */
    uint32_t  buf_len;          /* 0x10 — current input length */
    uint32_t  cursor_pos;       /* 0x14 — cursor position in input */
    uint32_t  flags;            /* 0x18 — mode flags */
    char      line_buf[128];    /* 0x1c — ← strcpy target (OVERFLOW HERE) */
} tt_readline_state_t;

/* tt_cshell debug shell listen ports (from strings in all acu_* binaries) */
#define TT_CSHELL_PORT_ACU_CTL      2323  /* acu_ctl debug shell */
#define TT_CSHELL_PORT_ACU_CTL_TSA  2330  /* acu_ctl TSA remote shell */
#define TT_CSHELL_PORT_ACU_VMU      2327  /* acu_vmu debug shell (all versions) */

/* tt_slog severity levels (used in tt_slog(level, fmt, ...) calls throughout) */
#define TT_LOG_EMERG    0
#define TT_LOG_ALERT    1
#define TT_LOG_CRIT     2
#define TT_LOG_ERR      3
#define TT_LOG_WARN     4
#define TT_LOG_NOTICE   5
#define TT_LOG_INFO     6
#define TT_LOG_DEBUG    7

/* tt_cshell function declarations (for r2 type propagation via aaft) */
void tt_slog(int level, const char *fmt, ...);
void tt_slogd(const char *fmt, ...);   /* debug-level shorthand */
void tt_printf(const char *fmt, ...);  /* local console print */

/* ══════════════════════════════════════════════════════════════════════════════
 * SECTION 2: VMU Network Setup Struct (DecodeIp overflow target)
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * HandleScAcunsMessage in acu_vmu (Explorer GX, binary cab13b2a) allocates a
 * 64-byte stack array (auStack_6c[64]) as a vmu_network_setup_t.
 * MdmG5::DecodeIp copies up to 32 bytes into each 16-byte IP field via strcpy,
 * causing inter-field overflow. The DNS field at offset +0x30 overflows into
 * 5 saved caller registers (r4–r8). See STACK_OVERFLOW_cab13b2a_1.md.
 */
typedef struct vmu_network_setup {
    char ip_addr[16];   /* 0x00 — IPv4 dotted-decimal string (16 bytes, incl. NUL) */
    char netmask[16];   /* 0x10 — subnet mask string */
    char gateway[16];   /* 0x20 — default gateway string */
    char dns[16];       /* 0x30 — DNS server string ← overflow here (32 bytes written) */
} vmu_network_setup_t;  /* sizeof = 0x40 = 64; overflow reaches saved r4..r8 at +0x5c */

/* MdmG5::DecodeIp — function type (see Finding STACK_OVERFLOW_cab13b2a) */
void MdmG5__DecodeIp(void *self, const char *input, const char *fmt, char *dest);
/* fmt examples: "IP#%32s", "MASK#%32s" — %32s + NUL = 33 bytes into 16-byte dest */

/* ══════════════════════════════════════════════════════════════════════════════
 * SECTION 3: PTRIA Protocol (acu_vmu port 6999 TLS)
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * The PTRIA (Pointing/Tracking/Remote Interface/Antenna) protocol is used by
 * acu_vmu on SAILOR 60GX/100GX to receive firmware updates and CRL certificates
 * from the Viasat satellite modem over mutual-TLS on TCP port 6999.
 *
 * Message type 0 (gen_data_xfer) triggers firmware install after CRC32 check.
 * Message type 7 replaces the CRL certificate file.
 * Neither operation is protected beyond the TLS client cert (which may be
 * fleet-shared or extractable from a compromised terminal).
 *
 * Reference: vault/Findings/CMD_INJECTION_539e9d11_1.md
 */

/* PTRIA gen_data_xfer types */
#define PTRIA_XFER_FIRMWARE   0   /* write to /tmp/upload → acu_cman.sh install */
#define PTRIA_XFER_CRL_CERT   7   /* write to /tmp/crl.cert_temp → mv to PKI dir */

/* PTRIA data transfer state block (partial; offset 0x198 holds transfer type) */
typedef struct ptria_xfer_state {
    uint8_t  _header[0x190];      /* 0x000 — session/connection fields (TBD) */
    uint32_t chunk_total;         /* 0x190 — expected total chunks */
    uint32_t chunk_received;      /* 0x194 — chunks received so far */
    uint32_t xfer_type;           /* 0x198 — transfer type (PTRIA_XFER_*) */
    char     tmp_path[256];       /* 0x19c — temp file path being written */
} ptria_xfer_state_t;             /* total size TBD — extend after deeper r2 analysis */

/* c_install_image — constructs and executes system() call chain */
int c_install_image(const char *firmware_path, int flags);
/* → system("/mnt/appl/bin/acu_cman.sh validate <path>") */
/* → system("/mnt/appl/bin/acu_cman.sh install  <path>") */

/* VMU modem credential keys (from configuration database) */
#define VMU_CFG_ROOT_PASSWORD     "root_password"
#define VMU_CFG_USER_PASSWORD     "user_password"
#define VMU_CFG_AUTH_USERNAME     "auth_username"
#define VMU_CFG_AUTH_PASSWORD     "auth_password"
#define VMU_CFG_DEBUG_SHELL_PASS  "DebugShellPassword"

/* ══════════════════════════════════════════════════════════════════════════════
 * SECTION 4: TIIF Firmware Image Format (suu — SUID root updater)
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * suu (firmware update utility) accepts TIIF (Thrane & Thrane Image Format)
 * files. It validates them with CRC32 ONLY — the embedded PKCS#7/RSA-4096/SHA-512
 * signature is NEVER verified (libssl/libcrypto linked but zero symbols imported).
 *
 * An attacker with admin access can craft a TIIF with arbitrary kernel/rootfs/
 * applfs SquashFS partitions, recalculate CRC32s (trivial — CRC32 is unkeyed),
 * and flash it via `suu install`. Full persistent root compromise.
 *
 * Reference: vault/Findings/UNSIGNED_FW_069d7d9a_suu_tiif.md
 * Pattern:   vault/Patterns/SUID_Firmware_CRC32_Only.md
 */

/* TIIF file magic (ASCII "FIITTIIF" as two big-endian u32s) */
#define TIIF_MAGIC_0   0x46494954  /* "FIIT" */
#define TIIF_MAGIC_1   0x54494946  /* "TIIF" */
#define TIIF_VERSION   0x01

/* TIIF file header (at offset 0x0000) */
typedef struct tiif_header {
    uint32_t magic_0;       /* 0x00 — 0x46494954 "FIIT" */
    uint32_t magic_1;       /* 0x04 — 0x54494946 "TIIF" */
    uint8_t  version;       /* 0x08 — must be 0x01 */
    uint8_t  _pad[3];       /* 0x09 — padding */
    uint32_t header_crc32;  /* 0x0c — CRC32 of bytes 0x10..header_len */
    uint32_t header_len;    /* 0x10 — length of this header */
    uint32_t body_crc32;    /* 0x14 — CRC32 of entire body after header */
    uint32_t body_len;      /* 0x18 — total body length */
    uint32_t content_count; /* 0x1c — number of content parts */
} tiif_header_t;            /* sizeof = 0x20 = 32 */

/* TIIF content part header (precedes each partition blob) */
typedef struct tiif_content_header {
    uint32_t header_crc32;  /* 0x00 — CRC32 of bytes 0x04..header_len */
    uint8_t  version;       /* 0x04 — must match tiif_header.version */
    uint8_t  _pad;          /* 0x05 */
    uint16_t header_len;    /* 0x06 — length of this content header */
    uint32_t body_len;      /* 0x08 — length of the partition body that follows */
    uint8_t  part_type;     /* 0x0c — partition type code (KNL1=3, ROOT1=4, APPL1=5) */
    uint8_t  flags;         /* 0x0d — content flags */
    uint16_t _pad2;         /* 0x0e */
    char     part_name[16]; /* 0x10 — partition label ("KNL1", "ROOT1", "APPL1", etc.) */
    /* sha256_hash[32] at 0x20 — PRESENT in header but NEVER CHECKED by suu */
    /* pkcs7_sig_ref  at 0x40 — offset into PKCS#7 manifest — NEVER CHECKED */
    uint32_t body_crc32;    /* 0x1c — CRC32 of partition body — THE ONLY CHECK */
} tiif_content_header_t;    /* sizeof = 0x20 = 32 (core fields; actual may be larger) */

/* TIIF partition type codes (part_type field) */
#define TIIF_PART_SUUM   2   /* suu module itself */
#define TIIF_PART_KNL1   3   /* Linux kernel (uImage, ARM) */
#define TIIF_PART_ROOT1  4   /* Root SquashFS filesystem */
#define TIIF_PART_APPL1  5   /* Application SquashFS filesystem */

/* Validation functions in suu (all CRC32-only; sig checking is ABSENT) */
uint32_t tiif_validate_header(const tiif_header_t *hdr);
uint32_t tiif_validate_content_header(const tiif_content_header_t *chdr);
uint32_t tiif_validate_content_body(const tiif_content_header_t *chdr, const void *body);
uint32_t tiif_validate_content_part(const tiif_content_header_t *chdr, const void *body);
uint32_t tiif_validate_body(const tiif_header_t *hdr, const void *body);

/* crc32_calc(seed, data) — internal CRC32 implementation in suu */
uint32_t crc32_calc(uint32_t seed, const void *data);

/* suu install entry point */
int suu_install(const char *tiif_path, int flags);
/* flags: -1 = force (skip model/version checks), 0 = normal */

/* Known good TIIF partition offsets in reference firmware (fw 1.66-9) */
#define TIIF_OFF_KERNEL     0x19A8      /* uImage, ARM zImage */
#define TIIF_OFF_ROOTFS     0x19F3EC    /* SquashFS #1 (rootfs, ~8.8MB) */
#define TIIF_OFF_APPLFS     0xA0E42C    /* SquashFS #2 (applfs, ~3.0MB) */

/* ══════════════════════════════════════════════════════════════════════════════
 * SECTION 5: CBUS IPC message bus (cbus_server)
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * cbus_server is the central IPC hub for all application processes on the
 * TT-7xxx platform. It uses a UNIX domain socket with zero authentication.
 * Any local process can register as any service, intercept messages, or inject
 * commands into the bus. acu_ctl receives CBUS message type 8 (manual upload)
 * and passes the payload into strcpy(arg1+0x31d4, arg2+0x14) — heap overflow.
 *
 * Reference: vault/Findings/AUTH_BYPASS_363a621a_1.md (cbus_server finding)
 */

/* CBUS IPC message header (best-effort layout from AduIfImpl::dispatch analysis) */
typedef struct cbus_msg {
    uint16_t msg_type;      /* 0x00 — message type code */
    uint16_t msg_len;       /* 0x02 — total message length including header */
    uint32_t src_service;   /* 0x04 — sender service ID */
    uint32_t dst_service;   /* 0x08 — destination service ID */
    uint32_t seq_no;        /* 0x0c — sequence number */
    uint32_t flags;         /* 0x10 — message flags */
    uint8_t  payload[1];    /* 0x14 — variable-length payload (msg_len - 0x14 bytes) */
} cbus_msg_t;               /* header = 0x14 = 20 bytes */

/* CBUS message types observed in acu_ctl AduIfImpl::dispatch (case labels) */
#define CBUS_MSG_MANUAL_UPLOAD  8   /* payload → strcpy(obj+0x31d4) — HEAP OVERFLOW */

/* AduIfImpl heap buffer overflow constants (acu_ctl binary 99fda815) */
#define ADUIFIMPL_UPLOAD_BUF_OFFSET  0x31d4  /* offset in AduIfImpl object of strcpy dest */

#endif /* COBHAM_TT_CSHELL_H */
