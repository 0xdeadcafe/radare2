/**
 * bmc_structs.h — Supermicro BMC / Aten IPMI type definitions
 *
 * Covers: ipmi.cgi, url_redirect.cgi, libipmi.so, and all CGI binaries in the
 *         Supermicro MBAST2500 BMC firmware (IPMI firmware v5.72.32).
 *
 * Basis:
 *   - ipmi.cgi r2 tag-table scan and r2ghidra pdg decompilation (binary acac7f0a, 2026-04-24)
 *   - libipmi.so r2ghidra pdg decompilation of sym.GetValue and sym.cgiGetPostVariable
 *   - vault/Findings/STACK_OVERFLOW_acac7f0a_ipmi_cgi_preauth.md
 *   - vault/Findings/SYSTEMIC_OVERFLOW_libipmi_cgiGetPostVariable.md
 *   - vault/Findings/AUTH_BYPASS_libweb_ip_session_supermicro.md
 *   - vault/Patterns/CGI_Tag_Dispatch_Auth_Bypass.md
 *
 * Architecture: ARM32 LE, ARMv5TEJ (ARM926EJ-S), no Thumb in CGI binaries
 * Target SoC:   Aten Pilot II / Pilot III (arm926ej-s variant)
 * Binary base:  CGI binaries at 0x8000 (fixed, no PIE), libipmi.so PIE (shared)
 * Mitigations:  NONE — no canary, no NX, no PIE on CGI binaries, no RELRO
 *
 * Load in r2:   to supermicro/bmc_structs.h
 * Auto-loaded:  profiles/supermicro-bmc-arm.r2
 *
 * Extend this file and run corpus_commit.py after new analysis sessions.
 */

#ifndef SUPERMICRO_BMC_STRUCTS_H
#define SUPERMICRO_BMC_STRUCTS_H

#include <stdint.h>
#include <stddef.h>

/* ── CGI tag dispatch entry ────────────────────────────────────────────────────
 * ipmi.cgi contains a flat array of 62 of these entries beginning at
 * .data+0x2FED8 (binary offset; base 0x8000). Each entry is 0x2C = 44 bytes.
 *
 * Layout verified by r2 pxw scan at 0x2FED8 (2026-04-24 session):
 *   offset 0x00–0x1f:  tag_name[32] — NUL-terminated XML action name string
 *   offset 0x20:       handler_fn   — pointer to per-tag handler function
 *   offset 0x24:       auth_required — 0 = pre-auth callable; 1 = session + CSRF
 *   offset 0x28:       min_privilege — minimum IPMI privilege level (0–5)
 *
 * CRITICAL: entry 58 ("HTML5_REFRESH.XML") has auth_required = 0 AND its
 * handler is reachable before check_session_api() is called. The POST value
 * for this tag is passed to strcpy(fp-0x3c, value) — 64 bytes to saved LR.
 *
 * Detection heuristic (r2):
 *   iz~HTML5,REFRESH,TAG         # find tag name strings
 *   /v 0x00                      # find auth_required=0 in .data
 *   pxw 0x30 @ 0x2FED8          # dump entry 58 directly
 */
typedef struct tag_dispatch_entry {
    char     tag_name[32];   /* 0x00 — XML action name, e.g. "HTML5_REFRESH.XML" */
    uint32_t handler_fn;     /* 0x20 — pointer to void handler(xml_buf*, int priv) */
    uint32_t auth_required;  /* 0x24 — 0 = pre-auth; 1 = requires session+CSRF+priv */
    uint32_t min_privilege;  /* 0x28 — IPMI priv level: 0=CALLBACK 1=USER 2=OPERATOR 3=ADMIN */
} tag_dispatch_entry_t;      /* sizeof = 0x2c = 44 */

/* IPMI privilege levels (min_privilege field) */
#define IPMI_PRIV_CALLBACK  0
#define IPMI_PRIV_USER      1
#define IPMI_PRIV_OPERATOR  2
#define IPMI_PRIV_ADMIN     3
#define IPMI_PRIV_OEM       4
#define IPMI_PRIV_NO_ACCESS 5

/* Number of entries in ipmi.cgi tag dispatch table */
#define IPMI_CGI_TAG_COUNT  62

/* ── IPMI CGI session data ────────────────────────────────────────────────────
 * On-stack struct in ipmi.cgi main(), at fp-0x0bc. Fields inferred from
 * r2ghidra decompilation and the check_session_api() call signature.
 *
 * check_session_api() writes into this struct; the validated session cookie and
 * privilege level are read back by the tag dispatch handler. When
 * tag->auth_required == 0, this struct is NEVER populated — the handler sees
 * zero-initialised fields.
 *
 * TODO: reverse check_session_api() in libipmi.so for exact field layout.
 *       Best current approximation from caller stack analysis.
 */
typedef struct ipmi_session {
    char     sid[64];        /* 0x00 — session ID string (from "SID" cookie/header) */
    uint32_t priv_level;     /* 0x40 — validated privilege level (IPMI_PRIV_*) */
    uint32_t uid;            /* 0x44 — authenticated user ID */
    char     username[32];   /* 0x48 — authenticated username */
    uint32_t csrf_valid;     /* 0x68 — 1 if CSRF token validated, 0 otherwise */
    uint32_t session_valid;  /* 0x6c — 1 if session cookie valid and not expired */
} ipmi_session_t;            /* sizeof = 0x70 = 112 (approximate) */

/* ── libipmi.so — cgiGetPostVariable / GetValue ───────────────────────────────
 * cgiGetPostVariable(param_name, max_length) heap-allocates a buffer from the
 * POST body sized to the ACTUAL data length, ignoring max_length entirely.
 * Callers that assume the returned pointer is bounded by max_length and copy it
 * to a fixed-size stack buffer via strcpy() are vulnerable to stack overflow.
 *
 * Vulnerable call pattern (ipmi.cgi main @ 0xba44):
 *   value = cgiGetPostVariable(tag->tag_name, 0x20);  // 0x20 NOT ENFORCED
 *   strcpy(fp - 0x3c, value);                          // OVERFLOW
 *
 * The 0x20 (32-byte) max_length parameter is passed through to GetValue() but
 * GetValue() computes the heap allocation size from the POST body scan loop
 * (var_18h = actual data length) — max_length is never read.
 *
 * Function declarations for r2 type propagation (aaft):
 */
char *cgiGetPostVariable(const char *param_name, int max_length);
/* Returns: heap-allocated string of actual POST value length, or NULL */

char *GetValue(const char *param_name, char **result_ptr, int max_length_ignored);
/* Internal — heap-allocates node + value buffer, writes ptr to *result_ptr */

/* ── HTTP/CGI environment helpers ─────────────────────────────────────────────
 * Standard CGI environment interface used by all BMC CGI binaries.
 * Declared here for r2ghidra type propagation.
 */
char *getenv(const char *name);           /* QUERY_STRING, HTTP_COOKIE, etc.  */
char *get_cgi_env(const char *name, int max); /* libipmi wrapper around getenv */

/* ── Session / CSRF validation functions (libipmi.so) ─────────────────────────
 * Called in authenticated tag handlers to validate the session cookie and CSRF
 * token. Completely skipped when tag_dispatch_entry.auth_required == 0.
 */
int check_session_api(ipmi_session_t *session_out);
/* Returns 0 on success, non-zero if session invalid or not found */

int validateCSRFToken(const char *token);
/* Returns 0 on success, non-zero if token absent or does not match session */

/* ── Overflow context constants ───────────────────────────────────────────────
 * Stack offsets for the exploitable overflow in ipmi.cgi main() (binary acac7f0a):
 *
 *   Overflow buffer:     fp - 0x3c   (12 usable bytes before adjacent variable)
 *   Saved frame pointer: fp + 0x000  (offset 60 from overflow buffer start)
 *   Saved LR (ret addr): fp + 0x004  (offset 64 from overflow buffer start)
 *
 * A 68-byte POST value for HTML5_REFRESH.XML gives full PC control.
 * No canary. Stack executable (no NX on ARM926EJ-S with this Linux config).
 */
#define IPMI_CGI_OVERFLOW_BUF_OFFSET   0x3c   /* fp - OFFSET = overflow buffer */
#define IPMI_CGI_OFFSET_TO_SAVED_FP    60     /* bytes from buf start to saved fp */
#define IPMI_CGI_OFFSET_TO_SAVED_LR    64     /* bytes from buf start to saved LR */

/* ── libweb.so — IP session bypass struct ─────────────────────────────────────
 * From AUTH_BYPASS_libweb_ip_session_supermicro.md.
 * libweb.so validates that the client IP in the HTTP header matches the IP
 * recorded in the session store. The session IP field is 16 bytes (IPv4 dotted
 * string). By sending an X-Forwarded-For or REMOTE_ADDR override equal to the
 * stored session IP, a remote attacker can hijack any session.
 *
 * TODO: fully reverse libweb.so session struct (session index, IP field offset).
 *       Approximate layout from string analysis and known exploit behavior.
 */
typedef struct web_session_entry {
    uint32_t session_id;     /* 0x00 — numeric session identifier */
    char     client_ip[16];  /* 0x04 — IPv4 string of client that created session */
    uint32_t priv_level;     /* 0x14 — IPMI_PRIV_* for this session */
    uint32_t uid;            /* 0x18 — user ID */
    uint32_t expire_time;    /* 0x1c — session expiry timestamp (epoch) */
    uint32_t csrf_token;     /* 0x20 — 32-bit CSRF token for this session */
} web_session_entry_t;       /* sizeof = 0x24 = 36 (approximate) */

#endif /* SUPERMICRO_BMC_STRUCTS_H */
