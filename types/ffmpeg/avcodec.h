/* FFmpeg libavcodec type definitions for radare2 */
/* Load in r2: to types/ffmpeg/avcodec.h */

#ifndef FFMPEG_AVCODEC_TYPES_H
#define FFMPEG_AVCODEC_TYPES_H

/* Codec IDs (common ones) */
enum AVCodecID {
    AV_CODEC_ID_NONE = 0,
    AV_CODEC_ID_MPEG1VIDEO = 1,
    AV_CODEC_ID_MPEG2VIDEO = 2,
    AV_CODEC_ID_H261 = 3,
    AV_CODEC_ID_H263 = 4,
    AV_CODEC_ID_RV10 = 5,
    AV_CODEC_ID_RV20 = 6,
    AV_CODEC_ID_MJPEG = 7,
    AV_CODEC_ID_MJPEGB = 8,
    AV_CODEC_ID_LJPEG = 9,
    AV_CODEC_ID_MPEG4 = 12,
    AV_CODEC_ID_RAWVIDEO = 13,
    AV_CODEC_ID_MSMPEG4V1 = 14,
    AV_CODEC_ID_MSMPEG4V2 = 15,
    AV_CODEC_ID_MSMPEG4V3 = 16,
    AV_CODEC_ID_WMV1 = 17,
    AV_CODEC_ID_WMV2 = 18,
    AV_CODEC_ID_H263P = 19,
    AV_CODEC_ID_H263I = 20,
    AV_CODEC_ID_FLV1 = 21,
    AV_CODEC_ID_H264 = 27,
    AV_CODEC_ID_VP3 = 35,
    AV_CODEC_ID_THEORA = 36,
    AV_CODEC_ID_VP5 = 60,
    AV_CODEC_ID_VP6 = 61,
    AV_CODEC_ID_VP6F = 62,
    AV_CODEC_ID_VP8 = 139,
    AV_CODEC_ID_VP9 = 167,
    AV_CODEC_ID_HEVC = 173,
    AV_CODEC_ID_AV1 = 226,
    /* Audio codecs start at 0x10000 */
    AV_CODEC_ID_PCM_S16LE = 0x10000,
    AV_CODEC_ID_PCM_S16BE = 0x10001,
    AV_CODEC_ID_PCM_U16LE = 0x10002,
    AV_CODEC_ID_PCM_U16BE = 0x10003,
    AV_CODEC_ID_PCM_S8 = 0x10004,
    AV_CODEC_ID_PCM_U8 = 0x10005,
    AV_CODEC_ID_PCM_MULAW = 0x10006,
    AV_CODEC_ID_PCM_ALAW = 0x10007,
    AV_CODEC_ID_PCM_S32LE = 0x10008,
    AV_CODEC_ID_PCM_S32BE = 0x10009,
    AV_CODEC_ID_PCM_U32LE = 0x1000a,
    AV_CODEC_ID_PCM_U32BE = 0x1000b,
    AV_CODEC_ID_PCM_S24LE = 0x1000c,
    AV_CODEC_ID_PCM_S24BE = 0x1000d,
    AV_CODEC_ID_PCM_F32LE = 0x10015,
    AV_CODEC_ID_PCM_F32BE = 0x10016,
    AV_CODEC_ID_PCM_F64LE = 0x10017,
    AV_CODEC_ID_PCM_F64BE = 0x10018,
    AV_CODEC_ID_ADPCM_IMA_QT = 0x11000,
    AV_CODEC_ID_ADPCM_IMA_WAV = 0x11001,
    AV_CODEC_ID_ADPCM_MS = 0x11006,
    AV_CODEC_ID_MP2 = 0x15000,
    AV_CODEC_ID_MP3 = 0x15001,
    AV_CODEC_ID_AAC = 0x15002,
    AV_CODEC_ID_AC3 = 0x15003,
    AV_CODEC_ID_DTS = 0x15004,
    AV_CODEC_ID_VORBIS = 0x15005,
    AV_CODEC_ID_WMAV1 = 0x15007,
    AV_CODEC_ID_WMAV2 = 0x15008,
    AV_CODEC_ID_FLAC = 0x1500c,
    AV_CODEC_ID_ALAC = 0x1500e,
    AV_CODEC_ID_OPUS = 0x1503c
};

/* Codec capabilities */
enum AVCodecCap {
    AV_CODEC_CAP_DRAW_HORIZ_BAND = 0x0001,
    AV_CODEC_CAP_DR1 = 0x0002,
    AV_CODEC_CAP_DELAY = 0x0020,
    AV_CODEC_CAP_SMALL_LAST_FRAME = 0x0040,
    AV_CODEC_CAP_SUBFRAMES = 0x0100,
    AV_CODEC_CAP_EXPERIMENTAL = 0x0200,
    AV_CODEC_CAP_CHANNEL_CONF = 0x0400,
    AV_CODEC_CAP_FRAME_THREADS = 0x1000,
    AV_CODEC_CAP_SLICE_THREADS = 0x2000,
    AV_CODEC_CAP_PARAM_CHANGE = 0x4000,
    AV_CODEC_CAP_VARIABLE_FRAME_SIZE = 0x10000,
    AV_CODEC_CAP_AVOID_PROBING = 0x20000,
    AV_CODEC_CAP_HARDWARE = 0x40000,
    AV_CODEC_CAP_HYBRID = 0x80000,
    AV_CODEC_CAP_ENCODER_REORDERED_OPAQUE = 0x100000
};

/* Codec flags */
enum AVCodecFlag {
    AV_CODEC_FLAG_UNALIGNED = 0x00000001,
    AV_CODEC_FLAG_QSCALE = 0x00000002,
    AV_CODEC_FLAG_4MV = 0x00000004,
    AV_CODEC_FLAG_OUTPUT_CORRUPT = 0x00000008,
    AV_CODEC_FLAG_QPEL = 0x00000010,
    AV_CODEC_FLAG_PASS1 = 0x00000200,
    AV_CODEC_FLAG_PASS2 = 0x00000400,
    AV_CODEC_FLAG_LOOP_FILTER = 0x00000800,
    AV_CODEC_FLAG_GRAY = 0x00002000,
    AV_CODEC_FLAG_PSNR = 0x00008000,
    AV_CODEC_FLAG_TRUNCATED = 0x00010000,
    AV_CODEC_FLAG_INTERLACED_DCT = 0x00040000,
    AV_CODEC_FLAG_LOW_DELAY = 0x00080000,
    AV_CODEC_FLAG_GLOBAL_HEADER = 0x00400000,
    AV_CODEC_FLAG_BITEXACT = 0x00800000,
    AV_CODEC_FLAG_AC_PRED = 0x01000000,
    AV_CODEC_FLAG_INTERLACED_ME = 0x20000000,
    AV_CODEC_FLAG_CLOSED_GOP = 0x80000000
};

/* Discard levels */
enum AVDiscard {
    AVDISCARD_NONE = 0xffffff10,
    AVDISCARD_DEFAULT = 0,
    AVDISCARD_NONREF = 8,
    AVDISCARD_BIDIR = 16,
    AVDISCARD_NONINTRA = 24,
    AVDISCARD_NONKEY = 32,
    AVDISCARD_ALL = 48
};

/* Picture types */
enum AVPictureType {
    AV_PICTURE_TYPE_NONE = 0,
    AV_PICTURE_TYPE_I = 1,
    AV_PICTURE_TYPE_P = 2,
    AV_PICTURE_TYPE_B = 3,
    AV_PICTURE_TYPE_S = 4,
    AV_PICTURE_TYPE_SI = 5,
    AV_PICTURE_TYPE_SP = 6,
    AV_PICTURE_TYPE_BI = 7
};

/* Codec structure */
struct AVCodec {
    char *name;
    char *long_name;
    int32_t type;           /* AVMediaType */
    int32_t id;             /* AVCodecID */
    int32_t capabilities;
    void *supported_framerates;  /* AVRational array, NULL terminated */
    void *pix_fmts;         /* AVPixelFormat array, -1 terminated */
    void *supported_samplerates; /* int array, 0 terminated */
    void *sample_fmts;      /* AVSampleFormat array, -1 terminated */
    void *channel_layouts;  /* uint64_t array, 0 terminated */
    uint8_t max_lowres;
    void *priv_class;       /* AVClass pointer */
    void *profiles;         /* AVProfile array */
    char *wrapper_name;
    /* Private fields follow */
};

/* Codec parameters */
struct AVCodecParameters {
    int32_t codec_type;     /* AVMediaType */
    int32_t codec_id;       /* AVCodecID */
    uint32_t codec_tag;
    void *extradata;
    int32_t extradata_size;
    int32_t format;         /* pixel/sample format */
    int64_t bit_rate;
    int32_t bits_per_coded_sample;
    int32_t bits_per_raw_sample;
    int32_t profile;
    int32_t level;
    int32_t width;
    int32_t height;
    struct AVRational sample_aspect_ratio;
    int32_t field_order;
    int32_t color_range;
    int32_t color_primaries;
    int32_t color_trc;
    int32_t color_space;
    int32_t chroma_location;
    int32_t video_delay;
    uint64_t channel_layout;
    int32_t channels;
    int32_t sample_rate;
    int32_t block_align;
    int32_t frame_size;
    int32_t initial_padding;
    int32_t trailing_padding;
    int32_t seek_preroll;
};

/* Codec context (simplified) */
struct AVCodecContext {
    void *av_class;         /* AVClass pointer */
    int32_t log_level_offset;
    int32_t codec_type;     /* AVMediaType */
    void *codec;            /* AVCodec pointer */
    int32_t codec_id;       /* AVCodecID */
    uint32_t codec_tag;
    void *priv_data;
    void *internal;
    void *opaque;
    int64_t bit_rate;
    int32_t bit_rate_tolerance;
    int32_t global_quality;
    int32_t compression_level;
    int32_t flags;
    int32_t flags2;
    void *extradata;
    int32_t extradata_size;
    struct AVRational time_base;
    int32_t ticks_per_frame;
    int32_t delay;
    int32_t width;
    int32_t height;
    int32_t coded_width;
    int32_t coded_height;
    int32_t gop_size;
    int32_t pix_fmt;        /* AVPixelFormat */
    void *draw_horiz_band;  /* callback */
    void *get_format;       /* callback */
    int32_t max_b_frames;
    float b_quant_factor;
    float b_quant_offset;
    int32_t has_b_frames;
    float i_quant_factor;
    float i_quant_offset;
    float lumi_masking;
    float temporal_cplx_masking;
    float spatial_cplx_masking;
    float p_masking;
    float dark_masking;
    int32_t slice_count;
    int32_t sample_aspect_ratio_num;
    int32_t sample_aspect_ratio_den;
    int32_t me_cmp;
    int32_t me_sub_cmp;
    int32_t mb_cmp;
    int32_t ildct_cmp;
    int32_t dia_size;
    int32_t last_predictor_count;
    int32_t me_pre_cmp;
    int32_t pre_dia_size;
    int32_t me_subpel_quality;
    int32_t me_range;
    int32_t slice_flags;
    int32_t mb_decision;
    void *intra_matrix;
    void *inter_matrix;
    int32_t intra_dc_precision;
    int32_t skip_top;
    int32_t skip_bottom;
    int32_t mb_lmin;
    int32_t mb_lmax;
    int32_t bidir_refine;
    int32_t keyint_min;
    int32_t refs;
    int32_t mv0_threshold;
    int32_t color_primaries;
    int32_t color_trc;
    int32_t colorspace;
    int32_t color_range;
    int32_t chroma_sample_location;
    int32_t slices;
    int32_t field_order;
    /* Audio */
    int32_t sample_rate;
    int32_t channels;
    int32_t sample_fmt;     /* AVSampleFormat */
    int32_t frame_size;
    int32_t frame_number;
    int32_t block_align;
    int32_t cutoff;
    uint64_t channel_layout;
    uint64_t request_channel_layout;
    int32_t audio_service_type;
    int32_t request_sample_fmt;
    /* ... many more fields ... */
};

/* Packet structure */
struct AVPacket {
    void *buf;              /* AVBufferRef pointer */
    int64_t pts;            /* presentation timestamp */
    int64_t dts;            /* decompression timestamp */
    void *data;
    int32_t size;
    int32_t stream_index;
    int32_t flags;
    void *side_data;        /* AVPacketSideData array */
    int32_t side_data_elems;
    int64_t duration;
    int64_t pos;            /* byte position in stream */
    void *opaque;
    void *opaque_ref;       /* AVBufferRef pointer */
    struct AVRational time_base;
};

/* Packet flags */
enum AVPacketFlag {
    AV_PKT_FLAG_KEY = 0x0001,
    AV_PKT_FLAG_CORRUPT = 0x0002,
    AV_PKT_FLAG_DISCARD = 0x0004,
    AV_PKT_FLAG_TRUSTED = 0x0008,
    AV_PKT_FLAG_DISPOSABLE = 0x0010
};

/* Function signatures */

/* Codec functions */
void *avcodec_find_decoder(int id);
void *avcodec_find_decoder_by_name(char *name);
void *avcodec_find_encoder(int id);
void *avcodec_find_encoder_by_name(char *name);

/* Context functions */
void *avcodec_alloc_context3(void *codec);
void avcodec_free_context(void **avctx);
int avcodec_open2(void *avctx, void *codec, void **options);
int avcodec_close(void *avctx);
int avcodec_parameters_to_context(void *codec, void *par);
int avcodec_parameters_from_context(void *par, void *codec);
int avcodec_parameters_copy(void *dst, void *src);

/* Decode/Encode */
int avcodec_send_packet(void *avctx, void *avpkt);
int avcodec_receive_frame(void *avctx, void *frame);
int avcodec_send_frame(void *avctx, void *frame);
int avcodec_receive_packet(void *avctx, void *avpkt);
void avcodec_flush_buffers(void *avctx);

/* Packet functions */
void *av_packet_alloc(void);
void av_packet_free(void **pkt);
void av_init_packet(void *pkt);
int av_new_packet(void *pkt, int size);
int av_packet_ref(void *dst, void *src);
void av_packet_unref(void *pkt);
void av_packet_move_ref(void *dst, void *src);
int av_packet_copy_props(void *dst, void *src);
void av_packet_rescale_ts(void *pkt, struct AVRational tb_src, struct AVRational tb_dst);

/* Version/config */
uint32_t avcodec_version(void);
char *avcodec_configuration(void);
char *avcodec_license(void);

#endif /* FFMPEG_AVCODEC_TYPES_H */
