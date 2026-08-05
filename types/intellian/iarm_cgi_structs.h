/**
 * iarm_cgi_structs.h — Intellian iARM-GX / iARM-nx type definitions
 *
 * Covers: nxagent.cgi, setagent.cgi, web_svc.cgi, acu_server, libcommon.so
 *
 * Basis:
 *   - nxagent.cgi r2ghidra pdg decompilation (binary 55a7d93c, 2026-04-25)
 *   - acu_server r2ghidra pdg decompilation (binary 2228aacf, 2026-04-25)
 *   - vault/Findings/CMD_INJECTION_55a7d93c_1.md
 *   - vault/Findings/CMD_INJECTION_acu_server_2228aacf.md
 *   - /etc/bim_user.cfg field analysis
 *
 * Load in r2: to /path/to/iarm_cgi_structs.h
 * Auto-loaded by: profiles/intellian-arm-glibc.r2
 *
 * Extend this file and run corpus_commit.py after new analysis sessions.
 */

#ifndef IARM_CGI_STRUCTS_H
#define IARM_CGI_STRUCTS_H

#include <stdint.h>
#include <stddef.h>

/* ── cJSON ────────────────────────────────────────────────────────────────────
 * Lightweight JSON parser used throughout nxagent.cgi and setagent.cgi.
 * Layout confirmed by: *(var_ch + 0x10) == valuestring in r2ghidra output
 * for NX_Json_Cmd_SENDUIF / NX_Json_Cmd_RUNUIF.
 * Source: cJSON v1.x (MIT) — embedded in lighttpd CGI binaries.
 */
typedef struct cJSON {
    struct cJSON *next;        /* 0x00 — linked list sibling */
    struct cJSON *prev;        /* 0x04 */
    struct cJSON *child;       /* 0x08 — first child (for objects/arrays) */
    int           type;        /* 0x0c — cJSON_False/True/NULL/Number/String/Array/Object */
    char         *valuestring; /* 0x10 — string value (used in CMD_INJECTION sinks) */
    int           valueint;    /* 0x14 — integer value (deprecated in cJSON 1.7.x) */
    double        valuedouble; /* 0x18 — float/double value */
    char         *string;      /* 0x20 — object key name */
} cJSON;

/* cJSON type constants */
#define cJSON_False  0
#define cJSON_True   1
#define cJSON_NULL   2
#define cJSON_Number 3
#define cJSON_String 4
#define cJSON_Array  5
#define cJSON_Object 6

/* ── NX JSON API request ──────────────────────────────────────────────────────
 * Inferred from nxagent.cgi dispatch: POST body contains:
 *   { "COMMAND": "<cmd>", "SID": "<session_id>", "PARAMS": { ... } }
 * The dispatch function extracts these three fields before calling a handler.
 */
typedef struct nx_json_request {
    char  *command;     /* "COMMAND" field — matched against dispatch table */
    char  *sid;         /* "SID" session cookie — validated by NX_Json_Check_Login_with_SID */
    cJSON *params;      /* "PARAMS" object — handler-specific parameters */
    cJSON *root;        /* root cJSON object (caller owns, freed after handler returns) */
} nx_json_request_t;

/* ── BIM user config entry ────────────────────────────────────────────────────
 * Parsed from /etc/bim_user.cfg and /etc/flash/eddy_user.cfg.
 * The config file uses key=value lines; this struct represents one user record.
 * Field sizes inferred from config file analysis and shadow entry format.
 *
 *   bim_user.cfg example:
 *     [user1]
 *     username=intellian
 *     password=12345678        (plaintext — confirmed default)
 *     privilege=2              (0=admin, 1=operator, 2=viewer)
 */
typedef struct bim_user_entry {
    char username[32];    /* 0x00 — login name */
    char password[64];    /* 0x20 — plaintext in .cfg; MD5crypt hash in /etc/shadow */
    int  privilege;       /* 0x60 — 0=admin 1=operator 2=viewer */
    int  uid;             /* 0x64 — UNIX uid (0 = root for admin accounts) */
} bim_user_entry_t;

/* Privilege levels */
#define BIM_PRIV_ADMIN    0
#define BIM_PRIV_OPERATOR 1
#define BIM_PRIV_VIEWER   2

/* ── UIF (Universal Interface Format) protocol message ───────────────────────
 * Used by acu_server on TCP:4002 (plaintext) and TCP:94002 (stunnel).
 * Full protocol spec not yet reversed; this is a best-effort struct from
 * the acu_server analysis (binary 2228aacf).
 *
 * Key attack path: UIF data field → sprintf → system()
 *   Format string: /bin/nx_monitor_tool senduif "%s" &
 *   Buffer: auStack_5ac[0x400] (1024 bytes) built from uif_msg.data
 *
 * TODO: reverse engineer exact byte layout from UIF parser in acu_server
 *       (fcn.0002cd60 at offset 0x2d1dc deals with the msg struct fields)
 */
typedef struct uif_msg {
    uint8_t  start_marker;  /* 0x00 — frame start (value TBD from pcap) */
    uint16_t command_id;    /* 0x01 — UIF command code */
    uint16_t length;        /* 0x03 — data payload length */
    uint8_t  data[1020];    /* 0x05 — command-specific payload */
    uint16_t checksum;      /* 0x3ff — CRC/checksum (TBD) */
} uif_msg_t;                /* total: 0x401 = 1025 bytes (unpadded) */

/* ── acu_server auth command buffer ──────────────────────────────────────────
 * make_acu_auth_command() in libcommon.so writes into a caller-supplied buffer:
 *   /bin/acu_tool --auth-acu-user "ESCAPED_USER" "ESCAPED_PASS"
 *
 * escape_expand() only escapes " and \ — backtick, $(), ;, | are NOT escaped.
 * This makes the login flow a command injection vector:
 *   username = `id > /tmp/pwned` → executes during auth attempt
 *
 * Buffer size inferred from the 0x200-byte local buffers observed in callers.
 */
typedef struct acu_auth_cmd_buf {
    char cmd[512]; /* 0x200 bytes — "/bin/acu_tool --auth-acu-user \"U\" \"P\"" */
} acu_auth_cmd_buf_t;

/* ── UIF_EXT_IF dispatch entry ───────────────────────────────────────────────
 * From acu_server.cfg UIF_EXT_IF entries and fcn.00028a58 analysis:
 *   UIF_EXT_IF = ["sbcast", "/bin/cgi_uif_storage_updater", 0, 0]
 *
 * The handler fork()+execl()s the configured command.
 * Field layout inferred from: *(arg1 + 0xc) = command path in fcn.00028a58
 */
typedef struct uif_ext_if_entry {
    char *uif_command;  /* 0x00 — UIF command string to match (e.g. "sbcast") */
    int   flags1;       /* 0x04 — purpose TBD */
    int   flags2;       /* 0x08 — purpose TBD */
    char *cmd_path;     /* 0x0c — shell command to execl() */
    int   param1;       /* 0x10 — arg1 passed to command */
    int   param2;       /* 0x14 — arg2 passed to command */
} uif_ext_if_entry_t;

/* ── CGI environment helper ──────────────────────────────────────────────────
 * nxagent.cgi uses cgiFormString() (from cgic library) to read POST/GET params.
 * This is the interface to the user-controlled data that reaches sprintf sinks.
 * Declaration here allows r2ghidra to produce cleaner decompilation output.
 */
int cgiFormString(const char *name, char *result, int max);
int cgiFormEntries(char ***ptrToList);
void cgiFree(void *ptr);

#endif /* IARM_CGI_STRUCTS_H */
