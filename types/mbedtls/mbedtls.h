/*
 * mbedTLS / Mbed TLS type definitions for radare2
 *
 * Covers mbedTLS 2.x and 3.x (API-compatible for most structs).
 * Common in embedded firmware: routers, SATCOM, industrial IoT, RTOS.
 *
 * Usage:
 *   to mbedtls/mbedtls.h
 *   tf mbedtls_ssl_handshake    # show signature
 *   tsc mbedtls_ssl_context     # show struct fields
 *
 * Load via profile or manually after analysis.
 */

/* ============================================================================
 * Error codes (mbedtls/error.h)
 * ============================================================================ */

enum mbedtls_err {
    MBEDTLS_ERR_SSL_WANT_READ          = -0x6900,  /* -26880 */
    MBEDTLS_ERR_SSL_WANT_WRITE         = -0x6880,  /* -26752 */
    MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS  = -0x6860,
    MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS = -0x6840,
    MBEDTLS_ERR_SSL_CONN_EOF           = -0x6800,
    MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY  = -0x7880,
    MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE  = -0x6A00,
    MBEDTLS_ERR_SSL_ALLOC_FAILED       = -0x7F00,
    MBEDTLS_ERR_NET_SOCKET_FAILED      = -0x0042,
    MBEDTLS_ERR_NET_CONNECT_FAILED     = -0x0044,
    MBEDTLS_ERR_NET_BIND_FAILED        = -0x0046,
    MBEDTLS_ERR_NET_LISTEN_FAILED      = -0x0048,
    MBEDTLS_ERR_NET_ACCEPT_FAILED      = -0x004E,
    MBEDTLS_ERR_NET_RECV_FAILED        = -0x004C,
    MBEDTLS_ERR_NET_SEND_FAILED        = -0x004E
};

/* ============================================================================
 * Cipher identifiers (mbedtls/cipher.h)
 * ============================================================================ */

enum mbedtls_cipher_id_t {
    MBEDTLS_CIPHER_ID_NONE = 0,
    MBEDTLS_CIPHER_ID_NULL = 1,
    MBEDTLS_CIPHER_ID_AES = 2,
    MBEDTLS_CIPHER_ID_DES = 3,
    MBEDTLS_CIPHER_ID_3DES = 4,
    MBEDTLS_CIPHER_ID_CAMELLIA = 5,
    MBEDTLS_CIPHER_ID_BLOWFISH = 6,
    MBEDTLS_CIPHER_ID_ARC4 = 7,
    MBEDTLS_CIPHER_ID_ARIA = 8,
    MBEDTLS_CIPHER_ID_CHACHA20 = 9
};

enum mbedtls_cipher_mode_t {
    MBEDTLS_MODE_NONE = 0,
    MBEDTLS_MODE_ECB = 1,
    MBEDTLS_MODE_CBC = 2,
    MBEDTLS_MODE_CFB = 3,
    MBEDTLS_MODE_OFB = 4,
    MBEDTLS_MODE_CTR = 5,
    MBEDTLS_MODE_GCM = 6,
    MBEDTLS_MODE_STREAM = 7,
    MBEDTLS_MODE_CCM = 8,
    MBEDTLS_MODE_XTS = 9,
    MBEDTLS_MODE_CHACHAPOLY = 10
};

/* ============================================================================
 * MD (hash) algorithm identifiers (mbedtls/md.h)
 * ============================================================================ */

enum mbedtls_md_type_t {
    MBEDTLS_MD_NONE    = 0,
    MBEDTLS_MD_MD2     = 1,
    MBEDTLS_MD_MD4     = 2,
    MBEDTLS_MD_MD5     = 3,
    MBEDTLS_MD_SHA1    = 4,
    MBEDTLS_MD_SHA224  = 5,
    MBEDTLS_MD_SHA256  = 6,
    MBEDTLS_MD_SHA384  = 7,
    MBEDTLS_MD_SHA512  = 8,
    MBEDTLS_MD_RIPEMD160 = 9
};

/* ============================================================================
 * Public key types (mbedtls/pk.h)
 * ============================================================================ */

enum mbedtls_pk_type_t {
    MBEDTLS_PK_NONE = 0,
    MBEDTLS_PK_RSA = 1,
    MBEDTLS_PK_ECKEY = 2,
    MBEDTLS_PK_ECKEY_DH = 3,
    MBEDTLS_PK_ECDSA = 4,
    MBEDTLS_PK_RSA_ALT = 5,
    MBEDTLS_PK_RSASSA_PSS = 6,
    MBEDTLS_PK_OPAQUE = 7
};

/* ============================================================================
 * SSL/TLS protocol states (mbedtls/ssl.h)
 * ============================================================================ */

enum mbedtls_ssl_states {
    MBEDTLS_SSL_HELLO_REQUEST           = 0,
    MBEDTLS_SSL_CLIENT_HELLO            = 1,
    MBEDTLS_SSL_SERVER_HELLO            = 2,
    MBEDTLS_SSL_SERVER_CERTIFICATE      = 3,
    MBEDTLS_SSL_SERVER_KEY_EXCHANGE     = 4,
    MBEDTLS_SSL_CERTIFICATE_REQUEST     = 5,
    MBEDTLS_SSL_SERVER_HELLO_DONE       = 6,
    MBEDTLS_SSL_CLIENT_CERTIFICATE      = 7,
    MBEDTLS_SSL_CLIENT_KEY_EXCHANGE     = 8,
    MBEDTLS_SSL_CERTIFICATE_VERIFY      = 9,
    MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC = 10,
    MBEDTLS_SSL_CLIENT_FINISHED         = 11,
    MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC = 12,
    MBEDTLS_SSL_SERVER_FINISHED         = 13,
    MBEDTLS_SSL_FLUSH_BUFFERS           = 14,
    MBEDTLS_SSL_HANDSHAKE_WRAPUP        = 15,
    MBEDTLS_SSL_HANDSHAKE_OVER          = 16,
    MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET = 17,
    MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT = 18
};

enum mbedtls_ssl_verify_mode {
    MBEDTLS_SSL_VERIFY_NONE     = 0,
    MBEDTLS_SSL_VERIFY_OPTIONAL = 1,
    MBEDTLS_SSL_VERIFY_REQUIRED = 2,
    MBEDTLS_SSL_VERIFY_UNSET    = 3
};

/* ============================================================================
 * Core structures (opaque types used as pointers in disassembly)
 *
 * These are intentionally simplified -- the real structures are large and
 * architecture-dependent. The key is recognising the type from call context.
 * ============================================================================ */

/* AES context: 276 bytes on 32-bit, 280 on 64-bit */
struct mbedtls_aes_context {
    int nr;                  /* number of rounds */
    int *rk;                 /* pointer to expanded key schedule */
    int buf[68];             /* key expansion buffer */
};

/* SHA-256 context: 104 bytes */
struct mbedtls_sha256_context {
    int total[2];            /* number of bytes processed */
    int state[8];            /* intermediate digest state */
    char buffer[64];         /* data block being processed */
    int is224;               /* 0 => SHA-256, else SHA-224 */
};

/* SHA-512 context: 212 bytes */
struct mbedtls_sha512_context {
    long long total[2];      /* number of bytes processed */
    long long state[8];      /* intermediate digest state */
    char buffer[128];        /* data block being processed */
    int is384;               /* 0 => SHA-512, else SHA-384 */
};

/* MD5 context: 92 bytes */
struct mbedtls_md5_context {
    int total[2];            /* number of bytes processed */
    int state[4];            /* intermediate digest state */
    char buffer[64];         /* data block being processed */
};

/* Generic public key context */
struct mbedtls_pk_context {
    void *pk_info;           /* pointer to pk_info_t vtable */
    void *pk_ctx;            /* underlying key data (rsa/ec) */
};

/* X.509 certificate (first fields, the real struct is 400+ bytes) */
struct mbedtls_x509_crt {
    int own_buffer;          /* indicator for buffer ownership */
    void *raw_p;             /* raw DER data pointer */
    int raw_len;             /* raw DER data length */
    void *tbs_p;             /* TBS (to-be-signed) data */
    int tbs_len;
    int version;             /* 1, 2, or 3 */
    /* ... serial, issuer, subject, validity, pk, sig ... */
};

/* SSL configuration (mbedtls_ssl_config) -- first key fields */
struct mbedtls_ssl_config {
    int endpoint;            /* 0 = server, 1 = client */
    int transport;           /* 0 = TLS stream, 1 = DTLS datagram */
    int authmode;            /* certificate verification mode */
    int allow_legacy_renegotiation;
    void *ca_chain;          /* trusted CA chain */
    void *ca_crl;            /* trusted CRL chain */
    void *key_cert;          /* own certificate/key list */
    /* ... min/max version, ciphersuite list, callbacks ... */
};

/* SSL context (mbedtls_ssl_context) -- first key fields */
struct mbedtls_ssl_context {
    void *conf;              /* pointer to mbedtls_ssl_config */
    int state;               /* enum mbedtls_ssl_states */
    int renego_status;       /* renegotiation state */
    int renego_records_seen;
    int major_ver;           /* TLS major version */
    int minor_ver;           /* TLS minor version */
    /* ... handshake, session, transform, input/output buffers ... */
};

/* Network context (simple int wrapper) */
struct mbedtls_net_context {
    int fd;                  /* file descriptor */
};

/* ============================================================================
 * Function signatures (mbedtls API)
 * ============================================================================ */

/* Initialization / free */
void mbedtls_ssl_init(struct mbedtls_ssl_context *ssl);
void mbedtls_ssl_free(struct mbedtls_ssl_context *ssl);
void mbedtls_ssl_config_init(struct mbedtls_ssl_config *conf);
void mbedtls_ssl_config_free(struct mbedtls_ssl_config *conf);
int mbedtls_ssl_config_defaults(struct mbedtls_ssl_config *conf, int endpoint, int transport, int preset);
int mbedtls_ssl_setup(struct mbedtls_ssl_context *ssl, struct mbedtls_ssl_config *conf);

/* Handshake and I/O */
int mbedtls_ssl_handshake(struct mbedtls_ssl_context *ssl);
int mbedtls_ssl_read(struct mbedtls_ssl_context *ssl, void *buf, int len);
int mbedtls_ssl_write(struct mbedtls_ssl_context *ssl, void *buf, int len);
int mbedtls_ssl_close_notify(struct mbedtls_ssl_context *ssl);
void mbedtls_ssl_set_bio(struct mbedtls_ssl_context *ssl, void *p_bio, void *f_send, void *f_recv, void *f_recv_timeout);
void mbedtls_ssl_set_timer_cb(struct mbedtls_ssl_context *ssl, void *p_timer, void *f_set_timer, void *f_get_timer);

/* Certificate / key */
int mbedtls_ssl_conf_ca_chain(struct mbedtls_ssl_config *conf, struct mbedtls_x509_crt *ca_chain, void *ca_crl);
int mbedtls_ssl_conf_own_cert(struct mbedtls_ssl_config *conf, struct mbedtls_x509_crt *own_cert, struct mbedtls_pk_context *pk_key);
void mbedtls_ssl_conf_authmode(struct mbedtls_ssl_config *conf, int authmode);
void mbedtls_ssl_conf_rng(struct mbedtls_ssl_config *conf, void *f_rng, void *p_rng);

/* Network helpers */
void mbedtls_net_init(struct mbedtls_net_context *ctx);
int mbedtls_net_connect(struct mbedtls_net_context *ctx, char *host, char *port, int proto);
int mbedtls_net_bind(struct mbedtls_net_context *ctx, char *bind_ip, char *port, int proto);
int mbedtls_net_accept(struct mbedtls_net_context *bind_ctx, struct mbedtls_net_context *client_ctx, void *client_ip, int buf_size, void *ip_len);
int mbedtls_net_recv(void *ctx, void *buf, int len);
int mbedtls_net_send(void *ctx, void *buf, int len);
void mbedtls_net_free(struct mbedtls_net_context *ctx);

/* AES */
void mbedtls_aes_init(struct mbedtls_aes_context *ctx);
void mbedtls_aes_free(struct mbedtls_aes_context *ctx);
int mbedtls_aes_setkey_enc(struct mbedtls_aes_context *ctx, void *key, int keybits);
int mbedtls_aes_setkey_dec(struct mbedtls_aes_context *ctx, void *key, int keybits);
int mbedtls_aes_crypt_ecb(struct mbedtls_aes_context *ctx, int mode, void *input, void *output);
int mbedtls_aes_crypt_cbc(struct mbedtls_aes_context *ctx, int mode, int length, void *iv, void *input, void *output);
int mbedtls_aes_crypt_cfb128(struct mbedtls_aes_context *ctx, int mode, int length, void *iv_off, void *iv, void *input, void *output);
int mbedtls_aes_crypt_ctr(struct mbedtls_aes_context *ctx, int length, void *nc_off, void *nonce_counter, void *stream_block, void *input, void *output);

/* SHA-256 / SHA-1 / MD5 */
void mbedtls_sha256_init(struct mbedtls_sha256_context *ctx);
void mbedtls_sha256_free(struct mbedtls_sha256_context *ctx);
int mbedtls_sha256_starts(struct mbedtls_sha256_context *ctx, int is224);
int mbedtls_sha256_update(struct mbedtls_sha256_context *ctx, void *input, int ilen);
int mbedtls_sha256_finish(struct mbedtls_sha256_context *ctx, void *output);
int mbedtls_sha256(void *input, int ilen, void *output, int is224);

/* SHA-512 */
void mbedtls_sha512_init(struct mbedtls_sha512_context *ctx);
void mbedtls_sha512_free(struct mbedtls_sha512_context *ctx);
int mbedtls_sha512_starts(struct mbedtls_sha512_context *ctx, int is384);
int mbedtls_sha512_update(struct mbedtls_sha512_context *ctx, void *input, int ilen);
int mbedtls_sha512_finish(struct mbedtls_sha512_context *ctx, void *output);
int mbedtls_sha512(void *input, int ilen, void *output, int is384);

/* MD5 */
void mbedtls_md5_init(struct mbedtls_md5_context *ctx);
void mbedtls_md5_free(struct mbedtls_md5_context *ctx);
int mbedtls_md5_starts(struct mbedtls_md5_context *ctx);
int mbedtls_md5_update(struct mbedtls_md5_context *ctx, void *input, int ilen);
int mbedtls_md5_finish(struct mbedtls_md5_context *ctx, void *output);
int mbedtls_md5(void *input, int ilen, void *output);

/* Generic MD interface */
void *mbedtls_md_info_from_type(int md_type);
int mbedtls_md(void *md_info, void *input, int ilen, void *output);
int mbedtls_md_hmac(void *md_info, void *key, int keylen, void *input, int ilen, void *output);

/* X.509 */
void mbedtls_x509_crt_init(struct mbedtls_x509_crt *crt);
void mbedtls_x509_crt_free(struct mbedtls_x509_crt *crt);
int mbedtls_x509_crt_parse(struct mbedtls_x509_crt *chain, void *buf, int buflen);
int mbedtls_x509_crt_parse_file(struct mbedtls_x509_crt *chain, char *path);
int mbedtls_x509_crt_parse_der(struct mbedtls_x509_crt *chain, void *buf, int buflen);

/* Public key */
void mbedtls_pk_init(struct mbedtls_pk_context *ctx);
void mbedtls_pk_free(struct mbedtls_pk_context *ctx);
int mbedtls_pk_parse_key(struct mbedtls_pk_context *ctx, void *key, int keylen, void *pwd, int pwdlen);
int mbedtls_pk_parse_public_key(struct mbedtls_pk_context *ctx, void *key, int keylen);
int mbedtls_pk_parse_keyfile(struct mbedtls_pk_context *ctx, char *path, char *password);
int mbedtls_pk_encrypt(struct mbedtls_pk_context *ctx, void *input, int ilen, void *output, void *olen, int osize, void *f_rng, void *p_rng);
int mbedtls_pk_decrypt(struct mbedtls_pk_context *ctx, void *input, int ilen, void *output, void *olen, int osize, void *f_rng, void *p_rng);
int mbedtls_pk_sign(struct mbedtls_pk_context *ctx, int md_alg, void *hash, int hash_len, void *sig, void *sig_len, void *f_rng, void *p_rng);
int mbedtls_pk_verify(struct mbedtls_pk_context *ctx, int md_alg, void *hash, int hash_len, void *sig, int sig_len);

/* Entropy and DRBG */
void mbedtls_entropy_init(void *ctx);
void mbedtls_entropy_free(void *ctx);
void mbedtls_ctr_drbg_init(void *ctx);
void mbedtls_ctr_drbg_free(void *ctx);
int mbedtls_ctr_drbg_seed(void *ctx, void *f_entropy, void *p_entropy, void *custom, int len);
int mbedtls_ctr_drbg_random(void *p_rng, void *output, int output_len);

/* Error string */
void mbedtls_strerror(int errnum, char *buffer, int buflen);
