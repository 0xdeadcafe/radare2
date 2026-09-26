# OpenSSL Type Definitions for radare2

Type definitions for the OpenSSL library (libssl and libcrypto).

## Files

| File | Contents |
|------|----------|
| `ssl.h` | SSL_CTX, SSL, SSL methods, connection functions |
| `crypto.h` | EVP digest/cipher, BIO, HMAC, error handling |

## Usage

```r2
# Load OpenSSL types
to types/openssl/ssl.h
to types/openssl/crypto.h

# Look up SSL errors
te ssl_error

# Look up verification errors
te x509_verify_error

# Look up cipher NIDs
te evp_nid

# Show function signature
tfc SSL_new
tfc EVP_DigestInit

# Apply struct to memory
tp EVP_CIPHER_CTX @ 0x1000
```

## Quick Reference

### SSL error codes
```
SSL_ERROR_NONE = 0         - No error
SSL_ERROR_SSL = 1          - Protocol error (check ERR)
SSL_ERROR_WANT_READ = 2    - Need more data to read
SSL_ERROR_WANT_WRITE = 3   - Need to write more data
SSL_ERROR_SYSCALL = 5      - System call error
SSL_ERROR_ZERO_RETURN = 6  - Clean shutdown
```

### SSL verify modes
```
SSL_VERIFY_NONE = 0        - No verification
SSL_VERIFY_PEER = 1        - Verify peer certificate
SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2  - Fail if no cert
```

### Common X509 verification errors
```
X509_V_OK = 0                              - OK
X509_V_ERR_CERT_HAS_EXPIRED = 10          - Certificate expired
X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18 - Self-signed
X509_V_ERR_HOSTNAME_MISMATCH = 62         - Hostname mismatch
```

### RSA padding modes
```
RSA_PKCS1_PADDING = 1      - PKCS#1 v1.5
RSA_PKCS1_OAEP_PADDING = 4 - PKCS#1 OAEP
RSA_PKCS1_PSS_PADDING = 6  - PKCS#1 PSS
```

## Common Analysis Patterns

### Identify TLS version negotiation
```r2
# Search for version constants
/x 0103  # TLS 1.0
/x 0203  # TLS 1.1  
/x 0303  # TLS 1.2
/x 0403  # TLS 1.3
```

### Track SSL_CTX creation
```r2
# Set breakpoint on SSL_CTX_new
db sym.SSL_CTX_new
dc
# Analyze method argument
tp SSL_METHOD @ rdi
```

### Analyze cipher usage
```r2
# Find EVP cipher initialization
axt sym.EVP_EncryptInit_ex
# Check cipher type at call sites
```

## Combining with zsigs

```r2
# Load Debian amd64 OpenSSL signatures
zo zigns/debian/amd64/libssl.zsig

# Load type information
to types/openssl/ssl.h
to types/openssl/crypto.h

# Analyze
aaa
z/              # Match signatures

# Annotate SSL_CTX at function argument
tp SSL_CTX @ rdi
```

## Architecture Notes

The struct definitions are for **64-bit Linux**. On 32-bit systems:
- Pointer sizes are 4 bytes instead of 8
- Some padding may differ
- Function parameter passing differs (stack vs registers)

OpenSSL structures are intentionally opaque in the API, so the struct 
definitions here are approximations based on the internal implementation.
Use them for guidance but verify against actual binary layouts.
