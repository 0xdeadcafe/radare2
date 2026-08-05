/* OpenSSL crypto type definitions for radare2 */
/* Load in r2: to types/openssl/crypto.h */

#ifndef OPENSSL_CRYPTO_TYPES_H
#define OPENSSL_CRYPTO_TYPES_H

/* EVP cipher/digest algorithm NIDs (selected common ones) */
enum evp_nid {
    NID_undef = 0,
    NID_md5 = 4,
    NID_sha1 = 64,
    NID_sha224 = 675,
    NID_sha256 = 672,
    NID_sha384 = 673,
    NID_sha512 = 674,
    NID_sha3_224 = 1096,
    NID_sha3_256 = 1097,
    NID_sha3_384 = 1098,
    NID_sha3_512 = 1099,
    NID_aes_128_cbc = 419,
    NID_aes_128_ecb = 418,
    NID_aes_128_gcm = 895,
    NID_aes_192_cbc = 423,
    NID_aes_192_ecb = 422,
    NID_aes_192_gcm = 898,
    NID_aes_256_cbc = 427,
    NID_aes_256_ecb = 426,
    NID_aes_256_gcm = 901,
    NID_des_cbc = 31,
    NID_des_ede3_cbc = 44,
    NID_rc4 = 5,
    NID_chacha20_poly1305 = 1018
};

/* EVP padding modes */
enum evp_padding {
    EVP_PADDING_PKCS7 = 1,
    EVP_PADDING_ISO7816_4 = 4,
    EVP_PADDING_ANSI923 = 5,
    EVP_PADDING_ISO10126 = 6,
    EVP_PADDING_ZERO = 7
};

/* RSA padding modes */
enum rsa_padding {
    RSA_PKCS1_PADDING = 1,
    RSA_SSLV23_PADDING = 2,
    RSA_NO_PADDING = 3,
    RSA_PKCS1_OAEP_PADDING = 4,
    RSA_X931_PADDING = 5,
    RSA_PKCS1_PSS_PADDING = 6
};

/* BIO types */
enum bio_type {
    BIO_TYPE_NONE = 0,
    BIO_TYPE_MEM = 1,
    BIO_TYPE_FILE = 2,
    BIO_TYPE_FD = 4,
    BIO_TYPE_SOCKET = 5,
    BIO_TYPE_NULL = 6,
    BIO_TYPE_SSL = 7,
    BIO_TYPE_CONNECT = 12,
    BIO_TYPE_ACCEPT = 13,
    BIO_TYPE_FILTER = 16,
    BIO_TYPE_BUFFER = 20,
    BIO_TYPE_BASE64 = 25
};

/* BIO control commands */
enum bio_ctrl {
    BIO_CTRL_RESET = 1,
    BIO_CTRL_EOF = 2,
    BIO_CTRL_INFO = 3,
    BIO_CTRL_SET = 4,
    BIO_CTRL_GET = 5,
    BIO_CTRL_PUSH = 6,
    BIO_CTRL_POP = 7,
    BIO_CTRL_GET_CLOSE = 8,
    BIO_CTRL_SET_CLOSE = 9,
    BIO_CTRL_PENDING = 10,
    BIO_CTRL_FLUSH = 11,
    BIO_CTRL_WPENDING = 13
};

/* X509 verification errors (selected) */
enum x509_verify_error {
    X509_V_OK = 0,
    X509_V_ERR_UNSPECIFIED = 1,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2,
    X509_V_ERR_UNABLE_TO_GET_CRL = 3,
    X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4,
    X509_V_ERR_CERT_SIGNATURE_FAILURE = 7,
    X509_V_ERR_CERT_NOT_YET_VALID = 9,
    X509_V_ERR_CERT_HAS_EXPIRED = 10,
    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18,
    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20,
    X509_V_ERR_CERT_CHAIN_TOO_LONG = 22,
    X509_V_ERR_CERT_REVOKED = 23,
    X509_V_ERR_NO_ISSUER_PUBLIC_KEY = 24,
    X509_V_ERR_HOSTNAME_MISMATCH = 62
};

/* EVP_MD_CTX - message digest context */
struct EVP_MD_CTX {
    void *digest;           /* EVP_MD pointer */
    void *engine;           /* ENGINE pointer */
    uint64_t flags;         /* flags */
    void *md_data;          /* digest-specific data */
    void *pctx;             /* EVP_PKEY_CTX pointer */
    void *update;           /* update function */
};

/* EVP_CIPHER_CTX - cipher context */
struct EVP_CIPHER_CTX {
    void *cipher;           /* EVP_CIPHER pointer */
    void *engine;           /* ENGINE pointer */
    int32_t encrypt;        /* 1 = encrypt, 0 = decrypt */
    int32_t buf_len;        /* partial block length */
    uint8_t oiv[16];        /* original IV */
    uint8_t iv[16];         /* working IV */
    uint8_t buf[32];        /* partial block buffer */
    int32_t num;            /* used for CFB/OFB/CTR modes */
    void *app_data;         /* application data */
    int32_t key_len;        /* key length */
    uint64_t flags;         /* flags */
    void *cipher_data;      /* cipher-specific data */
    int32_t final_used;     /* final block present */
    int32_t block_mask;     /* block size mask */
    uint8_t final[32];      /* final block */
};

/* BIO structure (simplified) */
struct BIO {
    void *method;           /* BIO_METHOD pointer */
    void *callback;         /* callback function */
    void *cb_arg;           /* callback argument */
    int32_t init;           /* initialized flag */
    int32_t shutdown;       /* shutdown mode */
    int32_t flags;          /* various flags */
    int32_t retry_reason;   /* retry reason */
    int32_t num;            /* fd or other number */
    void *ptr;              /* implementation-specific data */
    void *next_bio;         /* chain: next BIO */
    void *prev_bio;         /* chain: previous BIO */
    void *references;       /* reference count */
    uint64_t num_read;      /* bytes read */
    uint64_t num_write;     /* bytes written */
};

/* EVP message digest functions */
void *EVP_md5(void);
void *EVP_sha1(void);
void *EVP_sha224(void);
void *EVP_sha256(void);
void *EVP_sha384(void);
void *EVP_sha512(void);
void *EVP_sha3_224(void);
void *EVP_sha3_256(void);
void *EVP_sha3_384(void);
void *EVP_sha3_512(void);

void *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(void *ctx);
int EVP_DigestInit(void *ctx, void *type);
int EVP_DigestInit_ex(void *ctx, void *type, void *impl);
int EVP_DigestUpdate(void *ctx, void *d, uint64_t cnt);
int EVP_DigestFinal(void *ctx, void *md, uint32_t *s);
int EVP_DigestFinal_ex(void *ctx, void *md, uint32_t *s);
int EVP_Digest(void *data, uint64_t count, void *md, uint32_t *size, void *type, void *impl);

/* One-shot digest functions */
void *MD5(void *d, uint64_t n, void *md);
void *SHA1(void *d, uint64_t n, void *md);
void *SHA224(void *d, uint64_t n, void *md);
void *SHA256(void *d, uint64_t n, void *md);
void *SHA384(void *d, uint64_t n, void *md);
void *SHA512(void *d, uint64_t n, void *md);

/* EVP cipher functions */
void *EVP_aes_128_cbc(void);
void *EVP_aes_128_ecb(void);
void *EVP_aes_128_gcm(void);
void *EVP_aes_256_cbc(void);
void *EVP_aes_256_ecb(void);
void *EVP_aes_256_gcm(void);
void *EVP_des_cbc(void);
void *EVP_des_ede3_cbc(void);
void *EVP_chacha20_poly1305(void);

void *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(void *ctx);
int EVP_CIPHER_CTX_reset(void *ctx);
int EVP_EncryptInit(void *ctx, void *type, void *key, void *iv);
int EVP_EncryptInit_ex(void *ctx, void *type, void *impl, void *key, void *iv);
int EVP_EncryptUpdate(void *ctx, void *out, int *outl, void *in, int inl);
int EVP_EncryptFinal(void *ctx, void *out, int *outl);
int EVP_EncryptFinal_ex(void *ctx, void *out, int *outl);
int EVP_DecryptInit(void *ctx, void *type, void *key, void *iv);
int EVP_DecryptInit_ex(void *ctx, void *type, void *impl, void *key, void *iv);
int EVP_DecryptUpdate(void *ctx, void *out, int *outl, void *in, int inl);
int EVP_DecryptFinal(void *ctx, void *out, int *outl);
int EVP_DecryptFinal_ex(void *ctx, void *out, int *outl);
int EVP_CipherInit(void *ctx, void *type, void *key, void *iv, int enc);
int EVP_CipherUpdate(void *ctx, void *out, int *outl, void *in, int inl);
int EVP_CipherFinal(void *ctx, void *out, int *outl);

/* HMAC functions */
void *HMAC(void *evp_md, void *key, int key_len, void *d, uint64_t n, void *md, uint32_t *md_len);
void *HMAC_CTX_new(void);
void HMAC_CTX_free(void *ctx);
int HMAC_Init_ex(void *ctx, void *key, int len, void *md, void *impl);
int HMAC_Update(void *ctx, void *data, uint64_t len);
int HMAC_Final(void *ctx, void *md, uint32_t *len);

/* BIO functions */
void *BIO_new(void *type);
void *BIO_new_mem_buf(void *buf, int len);
void *BIO_new_file(char *filename, char *mode);
void *BIO_new_fp(void *stream, int close_flag);
void *BIO_new_socket(int sock, int close_flag);
int BIO_free(void *bio);
void BIO_free_all(void *bio);
int BIO_read(void *bio, void *data, int dlen);
int BIO_write(void *bio, void *data, int dlen);
int BIO_puts(void *bio, char *buf);
int BIO_gets(void *bio, char *buf, int size);
int64_t BIO_ctrl(void *bio, int cmd, int64_t larg, void *parg);
void *BIO_push(void *bio, void *append);
void *BIO_pop(void *bio);
int BIO_pending(void *bio);
int BIO_flush(void *bio);

/* Memory BIO */
void *BIO_s_mem(void);
int64_t BIO_get_mem_data(void *bio, char **pp);
void *BIO_new_mem_buf(void *buf, int len);

/* Base64 BIO */
void *BIO_f_base64(void);

/* Error handling */
uint64_t ERR_get_error(void);
uint64_t ERR_peek_error(void);
uint64_t ERR_peek_last_error(void);
void ERR_clear_error(void);
void ERR_error_string_n(uint64_t e, char *buf, uint64_t len);
char *ERR_error_string(uint64_t e, char *buf);
char *ERR_reason_error_string(uint64_t e);
void ERR_print_errors_fp(void *fp);

/* Random number generation */
int RAND_bytes(void *buf, int num);
int RAND_priv_bytes(void *buf, int num);
void RAND_seed(void *buf, int num);

/* Library initialization */
int OPENSSL_init_crypto(uint64_t opts, void *settings);
void OpenSSL_add_all_algorithms(void);
void OpenSSL_add_all_ciphers(void);
void OpenSSL_add_all_digests(void);
void OPENSSL_cleanup(void);

/* EVP Public Key */
void *EVP_PKEY_new(void);
void EVP_PKEY_free(void *pkey);
void *EVP_PKEY_CTX_new(void *pkey, void *e);
void *EVP_PKEY_CTX_new_id(int id, void *e);
void EVP_PKEY_CTX_free(void *ctx);
int EVP_PKEY_encrypt(void *ctx, void *out, void *outlen, void *in, int inlen);
int EVP_PKEY_decrypt(void *ctx, void *out, void *outlen, void *in, int inlen);
int EVP_PKEY_sign(void *ctx, void *sig, void *siglen, void *tbs, int tbslen);
int EVP_PKEY_verify(void *ctx, void *sig, int siglen, void *tbs, int tbslen);
int EVP_PKEY_keygen(void *ctx, void *ppkey);
int EVP_PKEY_keygen_init(void *ctx);
int EVP_PKEY_encrypt_init(void *ctx);
int EVP_PKEY_decrypt_init(void *ctx);

/* EVP Message Digest (extended) */
void *EVP_get_digestbyname(char *name);
void *EVP_get_cipherbyname(char *name);

/* PEM operations */
void *PEM_read_bio_X509(void *bp, void *x, void *cb, void *u);
void *PEM_read_bio_PrivateKey(void *bp, void *x, void *cb, void *u);
int PEM_write_bio_X509(void *bp, void *x);
int PEM_write_bio_PrivateKey(void *bp, void *key, void *enc, void *kstr, int klen, void *cb, void *u);

/* X.509 certificate */
void *X509_new(void);
void X509_free(void *a);
void *X509_get_pubkey(void *x);
int X509_verify_cert(void *ctx);
char *X509_verify_cert_error_string(long n);
void *X509_get_subject_name(void *x);
void *X509_get_issuer_name(void *x);

/* OpenSSL error (extended) */
void ERR_print_errors(void *bp);
char *ERR_lib_error_string(int err);
char *ERR_func_error_string(int err);

#endif /* OPENSSL_CRYPTO_TYPES_H */
