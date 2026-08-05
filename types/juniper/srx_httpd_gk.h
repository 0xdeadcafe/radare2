// Discovered from HTTPD-GK. (270d9123) — JunOS SRX 21.3R1.9
// DVPN token table entry — fields at known offsets from SA structures

typedef struct __attribute__((packed)) {
    char     ike_id[0xa8];          // 0x00: IKE identifier string
    char     sa_name[4];            // 0xa8: SA name (used in system() calls)
    char     pad1[0x344];           // 0xac-0x3ef: intermediate fields
    uint32_t ipsec_ip;              // 0x3f0: IPsec tunnel source IP
    char     pad2[4];               // 0x3f4
    uint32_t ipsec_field_3f8;       // 0x3f8: IPsec field (used in system() call)
    char     pad3[0x1e];            // 0x3fc-0x419
    uint8_t  flag_41a;              // 0x41a: branch flag in delete_sa
} dvpn_sa_entry_t;

typedef struct __attribute__((packed)) {
    char     username[64];
    char     token[128];
    char     ike_id[64];
    char     client_id[64];
    char     remote_ip[16];
    char     config_name[64];
    uint32_t ike_user_type;
    uint32_t ref_count;
} dvpn_token_entry_t;
