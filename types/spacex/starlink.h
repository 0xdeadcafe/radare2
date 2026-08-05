/**
 * starlink.h -- SpaceX Starlink user terminal type definitions for radare2
 *
 * Covers: sxverity on-disk format, gRPC UserClass auth taxonomy,
 *         emc WebSocket command bus (Slate/BwpProxy),
 *         gRPC dispatch table, swupdate structures
 *
 * Platform: AArch64 LE Linux (musl C++ + statically-linked Go)
 * Firmware: catson + catapult runtime 2026.03.27.mr76839.2
 *           (both runtimes are identical builds)
 * Blob hash: 2a45edecf2f9ba44b0ad099abd59cf91a14465343e6441a37b5c319bdfa3d353
 *
 * Basis:
 *   - user_terminal_frontend   (59003fd65aa6d645)  gRPC :9200
 *   - emc_web_socket_server    (fd54cbdb1172e3f9)  WebSocket :8065
 *   - user_mmut.project.so     (e4346034ab561b68)  MMUT plugin
 *   - uterm_binbox_user_terminal (50ef7d2345094c47) multi-call
 *
 * Findings:
 *   vault/Findings/STARLINK-APK-FIRMWARE-RECON-2026.md
 *   vault/Findings/STARLINK-RUNTIME-EXTRACTED-2026.md
 *   vault/Findings/AUTH_BYPASS_fd54cbdb_emc_ws_zero_auth.md
 *   vault/Findings/STARLINK-FRONTEND-GRPC-AUTH-TAXONOMY-2026.md
 *   vault/Findings/STARLINK-MMUT-GOD-USER-KEY-DISCLOSURE-2026.md
 *   vault/Findings/STARLINK-UNLOCK-SSH-INJECTION-2026.md
 *   vault/Findings/STARLINK-FRONTEND-LAN-RF-DISABLE-2026.md
 *
 * Load in r2:   to spacex/starlink.h
 * Profile:      . profiles/spacex-starlink-musl-arm64.r2
 *
 * Extend this file after new analysis sessions and run corpus_commit.py.
 */

#ifndef SPACEX_STARLINK_H
#define SPACEX_STARLINK_H

#include <stdint.h>
#include <stddef.h>

/* ==============================================================================
 * SECTION 1: sxverity on-disk container format
 *
 * SpaceX custom Merkle-hash integrity wrapper (NOT encrypted).
 * Similar to Linux dm-verity but as a file container rather than block device.
 *
 * Usage example in r2 (after loading this header):
 *   px 0x40 @ 0          ; dump header
 *   pf sxverity_header @ 0
 * ============================================================================== */

struct sxverity_header {
    char     magic[8];          /* "sxverity" -- magic bytes                     */
    uint32_t pad0;              /* always 0x00000000                             */
    uint32_t total_size;        /* LE32: total container size (bytes)            */
    uint32_t pad1;              /* always 0x00000000                             */
    uint32_t hash_tree_offset;  /* LE32: offset to hash tree (or hash count)     */
    uint32_t data_size;         /* LE32: size of data payload                    */
    uint32_t data_size_copy;    /* LE32: repeat of data_size (redundant field)   */
    uint32_t block_flags;       /* LE32: block size/flags (0x00000400 = 4096)    */
    uint8_t  hash_block1[20];   /* first 20 bytes of first SHA-256 hash block    */
    uint8_t  _pad_to_0x40[12];  /* zero padding to 0x40 boundary                */
    /* Additional 32-byte hash blocks continue from 0x040 to 0x1FF              */
    /* At offset 0x200: embedded rom1fs filesystem ("-rom1fs-" magic)           */
};
/* sizeof = 64 (0x40) -- struct covers only first hash block; full header is 512 bytes */

/* Partition names found in catson sxverity manifest                            */
#define SPACEX_PART_KERNEL      "Image.fit.ecc"         /* Linux FIT image     */
#define SPACEX_PART_RUNTIME     "runtime.sxv"           /* Runtime filesystem  */
#define SPACEX_PART_TFTP        "tftp.sxv"              /* TFTP recovery       */
#define SPACEX_PART_UTERM_BOOT  "SPACEX_CATSON_UTERMboot.bin"
#define SPACEX_PART_EMMC_BOOT   "SPACEX_CATSON_UTERM_EMMCboot.bin"
#define SPACEX_PART_XCVR_BOOT   "SPACEX_CATSON_TRANSCEIVERboot.bin"
/* Catapult uses A/B scheme: "boot.ab.prod.fip", "linux.ab.fip"                */

/* ==============================================================================
 * SECTION 2: gRPC UserClass authentication taxonomy
 *
 * Protobuf enum definition found at file offset 0xf4ca4d in
 * user_terminal_frontend (59003fd65aa6d645).
 *
 * Wire format at 0xf4ca4d:
 *   NO_USER\x10\x00\x12\x07\n\x03GOD\x10\x01\x12\x07\n\x03LAN\x10\x02 ...
 *
 * The gRPC server assigns UserClass based on the TLS connection type:
 *   - No TLS client cert     -> NO_USER (0)
 *   - LAN connection         -> LAN (2)   -- ANY device on 192.168.100.x
 *   - mTLS with Router CA    -> ROUTER (5)
 *   - SpaceX cloud cert      -> CLOUD (3) / CLOUD_INDIA (9)
 *   - Factory cert           -> FACTORY (4)
 *   - God-user signed req    -> GOD (1)
 *
 * Auth gate: grpcAuthCounterUpdate (0x529150) in user_terminal_frontend
 * ============================================================================== */

typedef enum SpaceX_UserClass {
    SPACEX_UC_NO_USER              = 0, /* Unauthenticated -- no TLS client cert          */
    SPACEX_UC_GOD                  = 1, /* God user -- Ed25519 signed; key held by SpaceX */
    SPACEX_UC_LAN                  = 2, /* Any device on 192.168.100.x (Starlink WiFi)   */
    SPACEX_UC_CLOUD                = 3, /* SpaceX cloud certificate (ECDSA P-384)        */
    SPACEX_UC_FACTORY              = 4, /* Factory provisioning mode                     */
    SPACEX_UC_ROUTER               = 5, /* mTLS with SpaceX Router CA (ECDSA P-384)      */
    SPACEX_UC_GUEST_LAN            = 6, /* Guest WiFi LAN user                           */
    SPACEX_UC_SENSITIVE_COMMANDING = 7, /* SensitiveCommand proto wrapper bearer         */
    SPACEX_UC_LAN_TLS              = 8, /* LAN user with TLS (distinct from plain LAN)   */
    SPACEX_UC_CLOUD_INDIA          = 9, /* India position export compliance key          */
} SpaceX_UserClass_t;

/* LAN-accessible operations (no auth beyond being on 192.168.100.x):
 *   DishInhibitRf     -> disable satellite radio          (CRITICAL -- service outage)
 *   DishInhibitGps    -> disable GPS/GNSS                 (CRITICAL -- geofencing failure)
 *   Reboot            -> force terminal restart           (DoS)
 *   Stow              -> physically retract dish          (physical impact)
 *   GetStatus         -> full terminal status read        (info disclosure)
 *   SideloadFileUpdate -> firmware sideload (sxverity gated)
 */

/* Auth gate structure -- set up inline before each grpcAuthCounterUpdate call  */
struct SpaceX_gRPC_auth_gate {
    SpaceX_UserClass_t allowed[8]; /* array of allowed UserClass values         */
    uint32_t           count;      /* number of valid entries in allowed[]      */
};

/* ==============================================================================
 * SECTION 3: gRPC dispatch table entry
 *
 * Each entry in HandleRequest (0x62d8d0) sets up an auth_gate then calls
 * grpcAuthCounterUpdate (0x529150) with the handler pointer and auth gate.
 *
 * Note: user_terminal_frontend is a statically-linked Go binary.
 * Function addresses are valid for binary hash 59003fd65aa6d645.
 * ============================================================================== */

struct SpaceX_gRPC_handler {
    void     *handler_fn;           /* handler function pointer (Go func)       */
    uint64_t  handler_type_ptr;     /* pointer to Go runtime type descriptor    */
    struct SpaceX_gRPC_auth_gate gate;
};

/* grpcAuthCounterUpdate inner check (user_terminal_frontend 0x52935c):
 *   cmp x7, x9         ; count vs loop index
 *   b.le -> UNIMPLEMENTED
 *   ldrsw x11, [x6, x9, lsl 2]  ; load gate.allowed[i]
 *   cmp w5, w11        ; actual_class == allowed?
 *   b.ne -> next entry
 *   (match) -> call handler
 */

/* ==============================================================================
 * SECTION 4: emc_web_socket_server Slate/BwpProxy command bus
 *
 * emc_web_socket_server binds TCP :8065 as a WebSocket server.
 * The SOLE auth gate is a Slate runtime flag: emc.test_device
 *
 * Production hardware: flag = false -> connection setup prints rejection,
 *                      returns 0, no message handler registered.
 *                      BUT: TCP port still open, WebSocket handshake completes.
 *
 * Test/Aviation/MMUT: flag = true  -> full command bus active, no further auth.
 *
 * Key function addresses (binary fd54cbdb1172e3f9):
 *   0x00028810  emc_conn_setup     -- connection entry, calls prod check once
 *   0x00028430  emc_prod_check     -- reads emc.test_device Slate key
 *   0x0002885c  b.eq 0x28a4c       -- branch: prod -> print rejection, return 0
 *   0x000288a8  (inline)           -- ldr x2,[x2,0xaa0]: register msg callback
 *   0x00029a04  emc_ws_msg_handler -- message handler (test devices only)
 *   0x0003e830  emc_arm_disarm     -- proxy_send_command_arm / disarm_all handler
 *   0x0003ddf4  emc_gnc_pause      -- proxy_gnc_pause handler
 * ============================================================================== */

/* Slate key names for emc_web_socket_server */
#define SPACEX_SLATE_TEST_DEVICE    "emc.test_device"
#define SPACEX_SLATE_NODE_DEFAULT   "user1"

/* WebSocket command strings (parsed in emc_ws_msg_handler 0x29a04) */
#define SPACEX_EMC_CMD_GET_SLATE    "websocket.get_slate"
#define SPACEX_EMC_CMD_SET_INT32    "si"     /* si <node>.<device> <int_value>  */
#define SPACEX_EMC_CMD_SET_FLOAT    "sf"     /* sf <node>.<device> <fp_value>   */
#define SPACEX_EMC_CMD_PROXY_CMD    "sc"     /* sc <command>                    */

/* BwpProxy satellite control commands */
#define SPACEX_BWP_ARM          "proxy_send_command_arm"
#define SPACEX_BWP_DISARM_ALL   "proxy_send_command_disarm_all"
#define SPACEX_BWP_GNC_PAUSE    "proxy_gnc_pause"
#define SPACEX_BWP_GNC_UNPAUSE  "proxy_gnc_unpause"
#define SPACEX_BWP_SET_INT32    "proxy_set_int32"
#define SPACEX_BWP_SET_FP       "proxy_set_fp"
#define SPACEX_BWP_ECEF_UPLOAD  "bwp_proxy_gnc_iss_ecef_state_upload"
#define SPACEX_BWP_GNC_STATE    "gnc_set_state_registry_var"

/* WebSocket rejection message (printed on prod hardware) */
#define SPACEX_EMC_PROD_REJECT  "This device is configured as Prod, and therefore will not accept external commands."

/* ==============================================================================
 * SECTION 5: Ed25519 public keys (extracted from firmware dat/)
 *
 * ALL keys below are PUBLIC keys only -- corresponding private keys held by SpaceX.
 * Disclosure exposes architecture; does NOT directly enable exploitation without
 * the private key.
 *
 * Sources:
 *   dat/common/unlock_verification_key      (production Ed25519 pubkey)
 *   dat/common/unlock_verification_dev_key  (dev Ed25519 pubkey)
 *   dat/model_user_terminal/swupdate_release_pubkey  (32-byte raw Ed25519)
 *   dat/common/swupdate_dev_pubkey          (32-byte raw Ed25519)
 * ============================================================================== */

/* unlock_verification_key (PEM, production) -- used by UnlockService
 * at user_terminal_frontend / uterm_binbox_user_terminal for root SSH injection */
#define SPACEX_UNLOCK_PUBKEY_PROD "MCowBQYDK2VwAyEAJ4tUpX9rxlBWYS027URbkFiJ7tt0Bj4UWGZr4cFqACk="
/* Base64(SPKI) of Ed25519 production public key for UnlockService             */

/* unlock_verification_dev_key (PEM, development) */
#define SPACEX_UNLOCK_PUBKEY_DEV "MCowBQYDK2VwAyEAU0hV/bf1Itw/+LZolyE003kQxFVUqSUIdsne+bLvfhA="

/* swupdate_release_pubkey (32-byte raw Ed25519) -- firmware signing key        */
/* fa7cd672 f1c65e51 8d7976fe 5cc4cab7 d3d07e51 6da59d55 89769a29 86a7c5ff     */

/* swupdate_dev_pubkey (32-byte raw Ed25519) -- dev firmware signing key        */
/* d0cf3034 4da6004d 4d0c7b84 ae2a4b65 370f9749 6b58477b f81bb560 0439920b     */

/* ==============================================================================
 * SECTION 6: swupdate artifact types
 * ============================================================================== */

typedef enum SpaceX_swupdate_type {
    SPACEX_SW_TYPE_UTERM           = 0, /* Catson / standard user terminal     */
    SPACEX_SW_TYPE_UTERM_CATAPULT  = 1, /* Catapult / HPv4 user terminal       */
    SPACEX_SW_TYPE_TRANSCEIVER     = 2, /* Phased array transceiver firmware   */
} SpaceX_swupdate_type_t;

/* ==============================================================================
 * SECTION 7: Network ports / services reference
 * ============================================================================== */

#define SPACEX_PORT_GRPC_PRIMARY    9200  /* user_terminal_frontend gRPC (TLS)  */
#define SPACEX_PORT_GRPC_SECONDARY  9201  /* secondary gRPC endpoint            */
#define SPACEX_PORT_EMC_WS          8065  /* emc_web_socket_server WebSocket (NO AUTH) */
#define SPACEX_PORT_DEBUG_HTTP      8080  /* user_terminal_frontend debug HTTP  */

/* Default gateway (Starlink router / dish) on local WiFi */
#define SPACEX_DEVICE_IP            "192.168.100.1"

#endif /* SPACEX_STARLINK_H */
