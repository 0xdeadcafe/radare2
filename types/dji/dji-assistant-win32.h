/*
 * DJI Windows Assistant API Type Definitions for radare2
 *
 * Usage: to types/dji/dji-assistant-win32.h
 *
 * Covers DJIAppModel key-value store, register_device request params,
 * DJI pack-list XML format, and the obfuscated string cipher used in
 * DJIUavService.dll (discovered 2026-05-06 from DJI Assistant 2 v2.1.40).
 *
 * Blob hash: 19fd03841a0e07ecf041b45832f776f7d9630184a8eecf063ff0812b3320c2bc
 */

/* ============================================================================
 * register_device API request parameters
 *   POST https://mydjiflight.dji.com/api/v2/register_device
 *   app_name: "dji_assistant"  (confirmed 2026-05-06)
 *   sign key: "QfWWouvQn5TnDO" (HMAC-SHA1, decrypted from DJIUavService.dll)
 * ============================================================================ */
typedef struct __attribute__((packed)) {
    char app_version[16];   /* "2.1.40.0" */
    char app_name[32];      /* "dji_assistant" */
    char device_sn[32];     /* device serial number */
    char os_platform[16];   /* "windows" */
    char os_version[32];    /* Windows version string */
    char api_version[4];    /* "1" */
    char lang[8];           /* "en" */
    char sign[64];          /* HMAC-SHA1 hex uppercase of concat(values) */
} dji_register_device_req_t;

/* ============================================================================
 * DJI pack-list XML format (server response)
 *   Root element: <dji_assistant>
 *   Child elements: <product> (one per firmware module)
 *   Cached locally: /DJIData/firm_cache/da2/csm/{product}/pack.list
 * ============================================================================ */
typedef struct {
    char product_type[32];
    char version[32];
    char url[256];
    char md5[33];
    uint32_t size;
} dji_pack_list_entry_t;

/* ============================================================================
 * DJI obfuscated string cipher (DJIUavService.dll, discovered 2026-05-06)
 *   Function: DJIUavService.dll VA 0x10276e97 (register_device builder)
 *   Algorithm: decrypted[i] = table[i%17] XOR ROR8(enc[i], i%8)
 *   17-byte table @ 0x106b2b80:
 *     {0x1f,0xf6,0xb8,0xca,0x50,0x3b,0x47,0xad,
 *      0x8d,0x04,0xd8,0x68,0x6d,0xcb,0x13,0xa0,0x00}
 *   Encrypted bytes (sign HMAC key):
 *     {0x4e,0x21,0xbf,0xec,0xf3,0xc9,0x4c,0x7e,
 *      0xe3,0x62,0x32,0x30,0x92,0x90,0xc4}
 *   Decrypted: "QfWWouvQn5TnDO" (14 bytes, HMAC-SHA1 key for sign param)
 * ============================================================================ */

/* ============================================================================
 * DJI AppModel key names (populated by DJIService.exe packed code)
 *   DJIAppModel singleton exported from DJIDevice.dll
 *   Keys used by addToUrlQuery() in register_device builder:
 * ============================================================================ */
#define DJI_APPMODEL_KEY_APP_VERSION  "app_version"   /* value: "2.1.40.0" */
#define DJI_APPMODEL_KEY_APP_NAME     "app_name"      /* value: "dji_assistant" */
#define DJI_APPMODEL_KEY_DEVICE_SN    "device_sn"
#define DJI_APPMODEL_KEY_OS_PLATFORM  "os_platform"   /* value: "windows" */
#define DJI_APPMODEL_KEY_OS_VERSION   "os_version"
#define DJI_APPMODEL_KEY_API_VERSION  "api_version"   /* value: "1" */
#define DJI_APPMODEL_KEY_LANG         "lang"          /* value: "en" */
#define DJI_APPMODEL_KEY_SIGN         "sign"

/* ============================================================================
 * HTTP headers for /getfile/getallfile (firmware manifest)
 *   Used by DJIFirmRegisterServiceAgent::GetSingleFirmData
 * ============================================================================ */
#define DJI_HEADER_DRONE_SN         "x-drone-sn"
#define DJI_HEADER_GL_SN            "x-gl-sn"
#define DJI_HEADER_RC_SN            "x-rc-sn"
#define DJI_HEADER_BATTERY_SN       "x-battery-sn"
#define DJI_HEADER_DRONE_FIRM_VER   "x-drone-firm-ver"
#define DJI_HEADER_APP_VER          "x-app-ver"      /* value: "2.1.40" */
#define DJI_HEADER_COUNTRY          "x-country"
#define DJI_HEADER_FS_APP_ID        "X-FS-App-ID"    /* value: "da2" (not app_name!) */
