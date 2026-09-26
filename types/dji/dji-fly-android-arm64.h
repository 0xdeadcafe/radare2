/*
 * DJI Fly Android ARM64 -- SDK type definitions
 * Source: DJI Fly 1.21.2 (dji.go.v5) -- libsdk_base.so, libsdk_jni.so, libwaes.so
 * Discovered: 2026-05-06
 *
 * Usage: to dji/dji-fly-android-arm64.h
 */

/* ---- Whitebox AES Keychain ---- */
/* RELA-populated at load time; accessed via get_key_chain_info(index) */
typedef struct {
    uint8_t  *ciphertext;    /* pointer to encrypted buffer (in LOAD2) */
    uint32_t  len;           /* plaintext length (48 for most creds)  */
    uint32_t  pad;
    uint8_t  *iv;            /* pointer to 16-byte AES-CBC IV          */
} uav_keychain_entry_t;

/* ---- Known Keychain Indices ---- */
typedef enum {
    UAV_KEYCHAIN_SYNC_WEBFR_SIGNING_KEY  = 0x3e,  /* CreateSignatureWithSHA1 */
    UAV_KEYCHAIN_UTMISS_SECRET_ID        = 0x4a,  /* UTMISS telemetry secret_id */
    UAV_KEYCHAIN_UTMISS_SIGNING_KEY      = 0x4b,  /* UTMISS signing_key */
} UAVWhiteBoxKeyChainInfoIndex;

/* ---- Keychain Secret Values ---- */
/*
 * Index 0x3e decrypted (PKCS7-padded, 32 bytes):
 *   "OZR5M6mB28x&88hGId2$JiEIhhfKlqVC"
 *   Used by: uav::sdk::SyncWebFRHandler::Sync (after-sales API)
 *
 * Index 0x4a decrypted (47 bytes, binary):
 *   09c20d5d9976bbf73bea2cde6f182725ab483c0fb31ffc2235da498b3dc8320e44d92a33f68e413d4812495835a4183a
 *   Used by: uav::sdk::utmiss::InitUtmissUpload (secret_id)
 *
 * Index 0x4b decrypted (47 bytes, binary):
 *   f0bca08f6f830135d3ecbc8352b09242df589ac50b561b6dbd8ee1d088e0c5383fa63dd49d66825b4ec37a00de0b9f6b
 *   Used by: uav::sdk::utmiss::InitUtmissUpload (signing_key)
 */

/* ---- WAES Algorithm (libsdk_base.so) ---- */
/*
 * WAES_decrypt_real(input, output, table@0x7416a0):
 *   1. InvShiftRows: perm = [0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3]
 *   2. S-box pass1:  output[i] = table[i*256 + shifted[i]]  (offsets 0x000-0xfff)
 *   3. mix_shift(output, sp_buf) via PLT -> VA 0x34c3e8
 *      Uses T0@0x213e10, T1@0x213f10, T2@0x214110, T3@0x214010 (MixColumns)
 *   4. S-box pass2:  output[i] = table[0x1000 + i*256 + sp_buf[i]]
 *
 * uav_white_box_decrypt(ciphertext, len, &result, iv):
 *   AES-128-CBC via WAES_decrypt_real; PKCS7 strip if last_byte <= 16
 */

/* ---- WAES Key Data (libsdk_base.so memory layout) ---- */
#define WAES_DECRYPT_TABLE_VA   0x7416a0   /* 8192 bytes: 32 x 256-entry S-boxes   */
#define WAES_MIXCOLS_T0_VA      0x213e10   /* 256 bytes: GF(2^8) MixColumns T0     */
#define WAES_MIXCOLS_T1_VA      0x213f10   /* 256 bytes: GF(2^8) MixColumns T1     */
#define WAES_MIXCOLS_T2_VA      0x214110   /* 256 bytes: GF(2^8) MixColumns T2     */
#define WAES_MIXCOLS_T3_VA      0x214010   /* 256 bytes: GF(2^8) MixColumns T3     */
#define KEYCHAIN_TABLE_VA       0x6d8d38   /* 1848 entries x 24 bytes              */
#define KEYCHAIN_ENTRY_SIZE     0x18       /* 24 bytes per entry                   */
#define KEYCHAIN_COUNT          0x738      /* 1848 total entries                   */

/* ---- StringFog (libwaes.so) ---- */
/*
 * nativeGetXXXX(encoded_bytes):
 *   decoded[i] = encoded[i] XOR key_table[(i % period) * 2]
 *   key_table  = "Y9*PI8B#gD^6Yhd1" (16 bytes at file 0x13dc7)
 *   period     = 8 (set by constructor at VA 0x1ed88)
 *
 * WhiteBoxAES.decryptFromWhiteBox(byte[]) -> String:
 *   AES-128-CBC via separate WAES table at VA 0x49110
 *   IV loaded from VA 0x127e0
 */

/* ---- Register Device API ---- */
/*
 * Server:   https://mydjiflight.dji.com/api/v2/register_device
 * Method:   POST application/x-www-form-urlencoded
 * Fields:   app_name, app_version, device_sn, os_platform, sign
 * app_name: "dji_fly"  (confirmed: passes server whitelist)
 * sign:     HMAC-SHA1(key, app_version + app_name + device_sn + os_platform)
 * key:      BLOCKED -- likely from WhiteBoxAES.decryptFromWhiteBox in DEX bytecode
 *           OR from a different keychain index (not yet identified)
 */
