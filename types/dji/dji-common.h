/*
 * DJI Common Type Definitions for radare2
 *
 * Usage: to types/dji/dji-common.h
 *
 * These types work with radare2's type system for:
 * - Applying types to memory: tp dji_imah_header @ 0
 * - Viewing enum values: te dji_module_kind
 * - Function signature matching
 */

/* ============================================================================
 * Module Type Enums
 * ============================================================================ */

/* Module kind (bits 0-4 of target byte) */
enum dji_module_kind {
    DJI_KIND_CAMERA = 1,
    DJI_KIND_MOBILE_APP = 2,
    DJI_KIND_FLYC = 3,
    DJI_KIND_GIMBAL = 4,
    DJI_KIND_CENTER = 5,
    DJI_KIND_REMOTE = 6,
    DJI_KIND_WIFI = 7,
    DJI_KIND_ENCODER = 8,
    DJI_KIND_LIGHTBRIDGE = 9,
    DJI_KIND_BATTERY_FW = 10,
    DJI_KIND_BATTERY_CTRL = 11,
    DJI_KIND_ESC = 12,
    DJI_KIND_DECODER = 13,
    DJI_KIND_LB_GROUND = 14,
    DJI_KIND_TX_USB = 15,
    DJI_KIND_RX_USB = 16,
    DJI_KIND_MVO = 17,
    DJI_KIND_FPGA_AIR = 19,
    DJI_KIND_FPGA_GND = 20,
    DJI_KIND_IMU = 25,
    DJI_KIND_RTK = 26,
    DJI_KIND_WIFI_GND = 27,
    DJI_KIND_PMU = 29
};

/* Common module codes (kind | model << 5) */
enum dji_module_code {
    DJI_MOD_CAMERA_APP = 0x0100,
    DJI_MOD_CAMERA_LDR = 0x0101,
    DJI_MOD_CAMERA_BST = 0x0102,
    DJI_MOD_FLYC_LDR = 0x0305,
    DJI_MOD_FLYC_APP = 0x0306,
    DJI_MOD_GIMBAL = 0x0400,
    DJI_MOD_CENTER = 0x0500,
    DJI_MOD_WIFI = 0x0700,
    DJI_MOD_ENCODER_DM368 = 0x0800,
    DJI_MOD_ENCODER_IG810 = 0x0801,
    DJI_MOD_LIGHTBRIDGE = 0x0900,
    DJI_MOD_BATTERY = 0x1100,
    DJI_MOD_ESC0 = 0x1200,
    DJI_MOD_ESC1 = 0x1201,
    DJI_MOD_ESC2 = 0x1202,
    DJI_MOD_ESC3 = 0x1203,
    DJI_MOD_DECODER = 0x1300,
    DJI_MOD_LB_GROUND = 0x1400,
    DJI_MOD_MVO_CAM = 0x1700,
    DJI_MOD_MVO_SONAR = 0x1701,
    DJI_MOD_IMU0 = 0x2500,
    DJI_MOD_IMU1 = 0x2501,
    DJI_MOD_RTK_APP = 0x2606,
    DJI_MOD_RTK_LDR = 0x2607,
    DJI_MOD_PMU_LDR = 0x2900,
    DJI_MOD_PMU_APP = 0x2901
};

/* ============================================================================
 * Encryption Key Enums
 * ============================================================================ */

/* Authentication key identifiers (4-char codes) */
enum dji_auth_key {
    DJI_AUTH_PRAK = 0x4b415250,
    DJI_AUTH_RRAK = 0x4b415252,
    DJI_AUTH_IAAK = 0x4b414149,
    DJI_AUTH_TRAK = 0x4b415254
};

/* Encryption key identifiers (4-char codes) */
enum dji_enc_key {
    DJI_ENC_PUEK = 0x4b455550,
    DJI_ENC_RIEK = 0x4b454952,
    DJI_ENC_IAEK = 0x4b454149,
    DJI_ENC_TRIE = 0x45495254,
    DJI_ENC_TKIE = 0x45494b54,
    DJI_ENC_TBIE = 0x45494254,
    DJI_ENC_UFIE = 0x45494655
};

/* ============================================================================
 * IM*H Header Version
 * ============================================================================ */

enum dji_imah_version {
    DJI_IMAH_2016 = 0,
    DJI_IMAH_2017 = 1,
    DJI_IMAH_2018 = 2
};

/* ============================================================================
 * DUPC Command Sets
 * ============================================================================ */

enum dji_dupc_cmdset {
    DJI_CMDSET_GENERAL = 0,
    DJI_CMDSET_SPECIAL = 1,
    DJI_CMDSET_CAMERA = 2,
    DJI_CMDSET_FLYC = 3,
    DJI_CMDSET_GIMBAL = 4,
    DJI_CMDSET_CENTER = 5,
    DJI_CMDSET_RADIO = 6,
    DJI_CMDSET_WIFI = 7,
    DJI_CMDSET_DM36X = 8,
    DJI_CMDSET_HD_LINK = 9,
    DJI_CMDSET_MBINO = 10,
    DJI_CMDSET_SIM = 11,
    DJI_CMDSET_ESC = 12,
    DJI_CMDSET_BATTERY = 13,
    DJI_CMDSET_DATA_LOG = 14,
    DJI_CMDSET_RTK = 15,
    DJI_CMDSET_AUTO = 16
};

/* DUPC sender/receiver IDs */
enum dji_dupc_sender {
    DJI_SENDER_CAMERA = 0x01,
    DJI_SENDER_APP = 0x02,
    DJI_SENDER_FLYC = 0x03,
    DJI_SENDER_GIMBAL = 0x04,
    DJI_SENDER_CENTER = 0x05,
    DJI_SENDER_RADIO = 0x06,
    DJI_SENDER_WIFI = 0x07,
    DJI_SENDER_DM36X = 0x08,
    DJI_SENDER_HD_LINK = 0x09,
    DJI_SENDER_PC = 0x0a,
    DJI_SENDER_BATTERY = 0x0b,
    DJI_SENDER_ESC = 0x0c,
    DJI_SENDER_RTK = 0x0d,
    DJI_SENDER_IMU = 0x0e
};

/* ============================================================================
 * Product Codes
 * ============================================================================ */

enum dji_product {
    DJI_PRODUCT_P3S = 0x100,
    DJI_PRODUCT_P3X = 0x101,
    DJI_PRODUCT_P3_4K = 0x102,
    DJI_PRODUCT_WM100 = 0x103,
    DJI_PRODUCT_WM220 = 0x104,
    DJI_PRODUCT_WM230 = 0x105,
    DJI_PRODUCT_WM240 = 0x106,
    DJI_PRODUCT_WM330 = 0x107,
    DJI_PRODUCT_WM331 = 0x108
};

/* ============================================================================
 * Ambarella Partition Types
 * ============================================================================ */

enum amba_part_type {
    AMBA_PART_SYS = 0,
    AMBA_PART_DSP = 1,
    AMBA_PART_LNX = 2,
    AMBA_PART_RFS = 3,
    AMBA_PART_ROM = 4
};
