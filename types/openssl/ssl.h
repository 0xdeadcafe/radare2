/* OpenSSL type definitions for radare2 */
/* Load in r2: to types/openssl/ssl.h */

#ifndef OPENSSL_SSL_TYPES_H
#define OPENSSL_SSL_TYPES_H

/* SSL/TLS method version constants */
enum ssl_version {
    SSL3_VERSION = 0x0300,
    TLS1_VERSION = 0x0301,
    TLS1_1_VERSION = 0x0302,
    TLS1_2_VERSION = 0x0303,
    TLS1_3_VERSION = 0x0304,
    DTLS1_VERSION = 0xFEFF,
    DTLS1_2_VERSION = 0xFEFD
};

/* SSL_CTX and SSL options */
enum ssl_options {
    SSL_OP_NO_SSLv3 = 0x02000000,
    SSL_OP_NO_TLSv1 = 0x04000000,
    SSL_OP_NO_TLSv1_1 = 0x10000000,
    SSL_OP_NO_TLSv1_2 = 0x08000000,
    SSL_OP_NO_TLSv1_3 = 0x20000000,
    SSL_OP_NO_DTLSv1 = 0x04000000,
    SSL_OP_NO_DTLSv1_2 = 0x08000000
};

/* SSL verify modes */
enum ssl_verify_mode {
    SSL_VERIFY_NONE = 0x00,
    SSL_VERIFY_PEER = 0x01,
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02,
    SSL_VERIFY_CLIENT_ONCE = 0x04,
    SSL_VERIFY_POST_HANDSHAKE = 0x08
};

/* SSL error codes */
enum ssl_error {
    SSL_ERROR_NONE = 0,
    SSL_ERROR_SSL = 1,
    SSL_ERROR_WANT_READ = 2,
    SSL_ERROR_WANT_WRITE = 3,
    SSL_ERROR_WANT_X509_LOOKUP = 4,
    SSL_ERROR_SYSCALL = 5,
    SSL_ERROR_ZERO_RETURN = 6,
    SSL_ERROR_WANT_CONNECT = 7,
    SSL_ERROR_WANT_ACCEPT = 8,
    SSL_ERROR_WANT_ASYNC = 9,
    SSL_ERROR_WANT_ASYNC_JOB = 10,
    SSL_ERROR_WANT_CLIENT_HELLO_CB = 11,
    SSL_ERROR_WANT_RETRY_VERIFY = 12
};

/* SSL shutdown modes */
enum ssl_shutdown {
    SSL_SENT_SHUTDOWN = 1,
    SSL_RECEIVED_SHUTDOWN = 2
};

/* SSL file types */
enum ssl_filetype {
    SSL_FILETYPE_PEM = 1,
    SSL_FILETYPE_ASN1 = 2
};

/* Opaque SSL structures - sizes are approximate for 64-bit */
struct SSL_CTX {
    void *method;           /* SSL_METHOD pointer */
    void *cert_store;       /* X509_STORE pointer */
    void *sessions;         /* session cache */
    uint64_t options;       /* SSL options */
    uint64_t mode;          /* SSL mode */
    int32_t verify_mode;    /* verification mode */
    int32_t verify_depth;   /* max verification depth */
    /* ... many more internal fields ... */
};

struct SSL {
    int32_t version;        /* protocol version */
    void *method;           /* SSL_METHOD pointer */
    void *rbio;             /* read BIO */
    void *wbio;             /* write BIO */
    void *bbio;             /* buffer BIO */
    int32_t rwstate;        /* read/write state */
    int32_t handshake_func; /* handshake function */
    void *server;           /* server name */
    int32_t new_session;    /* new session flag */
    int32_t quiet_shutdown; /* quiet shutdown flag */
    int32_t shutdown;       /* shutdown state */
    void *session;          /* SSL_SESSION pointer */
    void *ctx;              /* SSL_CTX pointer */
    /* ... many more internal fields ... */
};

/* SSL context functions */
void *SSL_CTX_new(void *method);
void SSL_CTX_free(void *ctx);
int64_t SSL_CTX_set_options(void *ctx, int64_t options);
int64_t SSL_CTX_clear_options(void *ctx, int64_t options);
int64_t SSL_CTX_get_options(void *ctx);
void SSL_CTX_set_verify(void *ctx, int mode, void *callback);
int SSL_CTX_set_verify_depth(void *ctx, int depth);
int SSL_CTX_load_verify_locations(void *ctx, char *CAfile, char *CApath);
int SSL_CTX_use_certificate_file(void *ctx, char *file, int type);
int SSL_CTX_use_certificate(void *ctx, void *x);
int SSL_CTX_use_PrivateKey_file(void *ctx, char *file, int type);
int SSL_CTX_use_PrivateKey(void *ctx, void *pkey);
int SSL_CTX_check_private_key(void *ctx);
void *SSL_CTX_get_cert_store(void *ctx);
int SSL_CTX_set_default_verify_paths(void *ctx);
int SSL_CTX_set_cipher_list(void *ctx, char *str);
int SSL_CTX_set_ciphersuites(void *ctx, char *str);
int SSL_CTX_set_min_proto_version(void *ctx, int version);
int SSL_CTX_set_max_proto_version(void *ctx, int version);

/* SSL connection functions */
void *SSL_new(void *ctx);
void SSL_free(void *ssl);
int SSL_set_fd(void *ssl, int fd);
int SSL_get_fd(void *ssl);
void SSL_set_bio(void *ssl, void *rbio, void *wbio);
void *SSL_get_rbio(void *ssl);
void *SSL_get_wbio(void *ssl);
int SSL_connect(void *ssl);
int SSL_accept(void *ssl);
int SSL_read(void *ssl, void *buf, int num);
int SSL_read_ex(void *ssl, void *buf, uint64_t num, uint64_t *readbytes);
int SSL_peek(void *ssl, void *buf, int num);
int SSL_write(void *ssl, void *buf, int num);
int SSL_write_ex(void *ssl, void *buf, uint64_t num, uint64_t *written);
int SSL_shutdown(void *ssl);
int SSL_get_error(void *ssl, int ret);
int SSL_get_shutdown(void *ssl);
void SSL_set_shutdown(void *ssl, int mode);
int SSL_pending(void *ssl);
int SSL_has_pending(void *ssl);

/* Certificate functions */
void *SSL_get_peer_certificate(void *ssl);
void *SSL_get0_peer_certificate(void *ssl);
void *SSL_get1_peer_certificate(void *ssl);
int64_t SSL_get_verify_result(void *ssl);
void *SSL_get_certificate(void *ssl);
void *SSL_get_privatekey(void *ssl);

/* Session functions */
void *SSL_get_session(void *ssl);
void *SSL_get0_session(void *ssl);
void *SSL_get1_session(void *ssl);
int SSL_set_session(void *ssl, void *session);
int SSL_session_reused(void *ssl);

/* Info functions */
char *SSL_get_version(void *ssl);
char *SSL_get_cipher(void *ssl);
void *SSL_get_current_cipher(void *ssl);
char *SSL_CIPHER_get_name(void *cipher);
int SSL_CIPHER_get_bits(void *cipher, int *alg_bits);
int SSL_get_state(void *ssl);

/* Method functions */
void *TLS_method(void);
void *TLS_server_method(void);
void *TLS_client_method(void);
void *SSLv23_method(void);
void *SSLv23_server_method(void);
void *SSLv23_client_method(void);
void *DTLS_method(void);
void *DTLS_server_method(void);
void *DTLS_client_method(void);

/* Library init/cleanup */
int OPENSSL_init_ssl(uint64_t opts, void *settings);
void SSL_load_error_strings(void);

/* TLS 1.3 / Modern TLS API */
int SSL_CTX_set1_curves_list(void *ctx, char *list);

/* ALPN negotiation */
int SSL_CTX_set_alpn_protos(void *ctx, void *protos, int protos_len);
void SSL_CTX_set_alpn_select_cb(void *ctx, void *cb, void *arg);
void SSL_get_alpn_selected(void *ssl, void *data, void *len);

/* Cipher info */
char *SSL_CIPHER_get_version(void *cipher);

/* Session management */
int SSL_CTX_set_session_cache_mode(void *ctx, int mode);
long SSL_CTX_sess_set_cache_size(void *ctx, long t);

/* BIO interface */
void *BIO_new(void *type);
void *BIO_new_mem_buf(void *buf, int len);
int BIO_read(void *b, void *data, int len);
int BIO_write(void *b, void *data, int len);
int BIO_free(void *a);

#endif /* OPENSSL_SSL_TYPES_H */
