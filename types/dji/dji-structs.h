/*
 * DJI Firmware Structure Definitions for radare2
 *
 * Usage: to types/dji/dji-structs.h
 *
 * Note: These structs use basic C types compatible with r2's parser.
 * For more precise field display, use pf format strings in firmware.pf
 */

/* ============================================================================
 * xV4 Firmware Package Structures
 * ============================================================================ */

/* xV4 main header - 64 bytes
 * Magic: 0x12345678 at offset 0 */
struct dji_xv4_header {
    int magic;
    short magic_ver;
    short reserved1;
    int hdrend_offs;
    int timestamp;
    char manufacturer[16];
    char model[16];
    short entry_count;
    int ver_latest_enc;
    int ver_rollbk_enc;
    char padding[10];
};

/* xV4 module entry - 52 bytes */
struct dji_xv4_entry {
    char target;
    char spcoding;
    short reserved2;
    int version;
    int dt_offs;
    int stored_len;
    int decrypted_len;
    char stored_md5[16];
    char decrypted_md5[16];
};

/* ============================================================================
 * IM*H Signed Module Structures
 * ============================================================================ */

/* IM*H header - 192 bytes
 * Magic: "IM*H" at offset 0 */
struct dji_imah_header {
    char magic[4];
    int header_version;
    int size;
    char reserved[4];
    int header_size;
    int signature_size;
    int payload_size;
    int target_size;
    char os;
    char arch;
    char compression;
    char anti_version;
    int auth_alg;
    char auth_key[4];
    char enc_key[4];
    char scram_key[16];
    char name[32];
    char type[4];
    int version;
    int date;
    int encr_cksum;
    char reserved2[16];
    char userdata[16];
    char entry[8];
    int plain_cksum;
    int chunk_num;
    char payload_digest[32];
};

/* IM*H chunk header - 32 bytes */
struct dji_imah_chunk {
    char id[4];
    int offset;
    int size;
    int attrib;
    long address;
    char reserved[8];
};

/* ============================================================================
 * Mavic FC Encryption Header
 * ============================================================================ */

/* MVFC header - 41 bytes */
struct dji_mvfc_header {
    char target;
    int unk0;
    char version[4];
    char unk1;
    int size;
    int unk2;
    int time;
    char unk3;
    char md5[16];
    short crc16;
};

/* ============================================================================
 * DUPC Protocol Structures
 * ============================================================================ */

/* DUPC 0x55 packet header - 4 bytes */
struct dji_dupc55_hdr {
    char magic;
    short length_ver;
    char hcrc;
};

/* DUPC 0x55 full header - 13 bytes */
struct dji_dupc55_full {
    char magic;
    short length_ver;
    char hcrc;
    char src;
    char dst;
    short seq;
    char cmd_type;
    char cmd_set;
    char cmd_id;
    char padding;
};

/* DUPC 0xAB packet header - 4 bytes */
struct dji_dupcab_hdr {
    char magic;
    char length;
    char flags1;
    char flags2;
};

/* ============================================================================
 * FlyC Parameter Structures
 * ============================================================================ */

/* FlyC parameter entry */
struct dji_flyc_param {
    int hash;
    short type;
    char name[32];
};

/* ============================================================================
 * Ambarella Structures
 * ============================================================================ */

/* Ambarella main header - 40 bytes */
struct amba_header {
    char model_name[32];
    int ver_info;
    int crc32;
};

/* Ambarella partition header - 256 bytes
 * Magic: 0xA324EB90 at offset 24 */
struct amba_part_header {
    int crc32;
    int version;
    int build_date;
    int dt_len;
    int mem_addr;
    int flag1;
    int magic;
    int flag2;
    char padding[224];
};

/* Ambarella ROMFS header - 8 bytes visible
 * Magic: 0x66FC328A at offset 4 */
struct amba_romfs_header {
    int file_count;
    int magic;
};

/* Ambarella ROMFS file entry - 128 bytes
 * Magic: 0x2387AB76 at offset 124 */
struct amba_romfs_entry {
    char filename[116];
    int offset;
    int length;
    int magic;
};

/* ============================================================================
 * Encryption Key Info
 * ============================================================================ */

struct dji_key_info {
    char enc_key[4];
    char auth_key[4];
    char reserved[8];
};

/* ============================================================================
 * DUML Framework (libduml_frwk.so) -- Event/DUPC Dispatcher Structures
 * Discovered from: wm240 libduml_frwk.so (8073dc82), 2026-05-05
 * ============================================================================ */

/* DUPC v1 parsed message header (13-byte raw + decoded fields)
 * Stored at msg_ptr after mb_parse_message_v1() succeeds.
 * Field layout confirmed by decompiling sym.mb_parse_message_v1 @ 0x1f7e0 */
struct duss_event_msg_t {
    char   magic;          /* 0x00: always 0x21 after parse */
    char   pad1;           /* 0x01 */
    char   version;        /* 0x02: 0x12 */
    char   pad2;           /* 0x03: 0xAD */
    int    src_module;     /* 0x04: source module ID (decoded from raw[4]/[5]) */
    int    dst_module;     /* 0x06: destination module ID */
    int    frame_seq;      /* 0x08: frame sequence number (raw[6]) */
    short  flags;          /* 0x0A: command type flags (raw[8]) */
    int    cmd_id_set;     /* 0x0C: combined (cmd_set << 16) | cmd_id  <- KEY FIELD */
    int    payload_size;   /* 0x10: payload length in bytes */
    char*  payload_ptr;    /* 0x14 (stack var): pointer to payload data */
};

/* cmd_desc entry (12 bytes each, indexed as cmd_id * 0xc + table[cmd_set])
 * Returned by event_get_cmd_desc (fcn.00048720 in libduml_frwk.so).
 * Offset 0: request handler fn ptr, offset 4: response handler fn ptr */
struct duss_cmd_desc_t {
    void*  request_handler;   /* 0x00: called for requests (send path) */
    void*  response_handler;  /* 0x04: called for responses (recv path) */
    int    flags;             /* 0x08: bit31=async; bit0=requires_resp */
};

/* DUPC cmd_set identifiers -- confirmed by protocol trace strings in libduml_frwk.so */
enum duss_cmd_set {
    DUSS_CMDSET_GENERAL    = 0x00,
    DUSS_CMDSET_SPECIAL    = 0x01,
    DUSS_CMDSET_CAMERA     = 0x02,
    DUSS_CMDSET_FC         = 0x03,
    DUSS_CMDSET_GIMBAL     = 0x04,
    DUSS_CMDSET_CENTER     = 0x05,
    DUSS_CMDSET_RC         = 0x06,
    DUSS_CMDSET_WIFI       = 0x07,   /* <- P3C cmd injection: cmd_set=0x07, cmd_id=0x10 */
    DUSS_CMDSET_BATTERY    = 0x0A,
    DUSS_CMDSET_ADSB       = 0x0B,
    DUSS_CMDSET_SYS        = 0x10,   /* <- dji_sys upgrade handlers */
    DUSS_CMDSET_MAX        = 0x23    /* Maximum cmd_set (bounds check in dispatcher) */
};
