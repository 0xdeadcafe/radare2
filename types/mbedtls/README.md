# types/mbedtls/ — Mbed TLS / mbedTLS type definitions

Type definitions for mbedTLS 2.x / 3.x (Mbed TLS), the most common TLS library
in embedded firmware (routers, SATCOM, industrial IoT, RTOS).

## Usage

```r2
to mbedtls/mbedtls.h
tf mbedtls_ssl_handshake     # show SSL handshake signature
tf mbedtls_aes_crypt_cbc     # show AES-CBC signature
tsc mbedtls_ssl_context      # show SSL context struct
tsc mbedtls_aes_context      # show AES context struct
te mbedtls_ssl_states        # show SSL handshake state enum
te mbedtls_md_type_t         # show hash algorithm enum
```

## Coverage

| Header area | Types |
|-------------|-------|
| SSL/TLS | `mbedtls_ssl_context`, `mbedtls_ssl_config`, states enum |
| Certificates | `mbedtls_x509_crt`, `mbedtls_pk_context` |
| Symmetric | `mbedtls_aes_context`, AES functions |
| Hash | `mbedtls_sha256_context`, `mbedtls_sha512_context`, `mbedtls_md5_context` |
| Network | `mbedtls_net_context` |
| Error codes | `mbedtls_err` enum |
| Cipher/MD IDs | `mbedtls_cipher_id_t`, `mbedtls_md_type_t` |

## Target Profiles

This file is loaded by:
- `profiles/linux-musl-arm64.r2` (if mbedtls detected)
- `profiles/linux-musl-armv7.r2`
- `profiles/openwrt-mips_24kc.r2`
- `profiles/linux-uclibc-mips.r2`
- `profiles/vxworks7-x86_64.r2` (already has `libmbedtls_hash.zsig`)
- Add manually: `to mbedtls/mbedtls.h`

## Notes

- `mbedtls_ssl_context` and `mbedtls_ssl_config` structs are simplified;
  the real structs are architecture-dependent and 200–500 bytes.
- Key analysis technique: find `mbedtls_ssl_handshake` → follow call chain
  to identify the server/client auth path and certificate verification.
- `MBEDTLS_SSL_VERIFY_NONE` in `conf->authmode` = skipped cert check (vulnerability).
