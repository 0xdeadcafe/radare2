/* FFmpeg libavutil type definitions for radare2 */
/* Load in r2: to types/ffmpeg/avutil.h */

#ifndef FFMPEG_AVUTIL_TYPES_H
#define FFMPEG_AVUTIL_TYPES_H

/* Pixel formats (common ones) */
enum AVPixelFormat {
    AV_PIX_FMT_NONE = 0xffffffff,
    AV_PIX_FMT_YUV420P = 0,
    AV_PIX_FMT_YUYV422 = 1,
    AV_PIX_FMT_RGB24 = 2,
    AV_PIX_FMT_BGR24 = 3,
    AV_PIX_FMT_YUV422P = 4,
    AV_PIX_FMT_YUV444P = 5,
    AV_PIX_FMT_YUV410P = 6,
    AV_PIX_FMT_YUV411P = 7,
    AV_PIX_FMT_GRAY8 = 8,
    AV_PIX_FMT_MONOWHITE = 9,
    AV_PIX_FMT_MONOBLACK = 10,
    AV_PIX_FMT_PAL8 = 11,
    AV_PIX_FMT_YUVJ420P = 12,
    AV_PIX_FMT_YUVJ422P = 13,
    AV_PIX_FMT_YUVJ444P = 14,
    AV_PIX_FMT_NV12 = 25,
    AV_PIX_FMT_NV21 = 26,
    AV_PIX_FMT_ARGB = 27,
    AV_PIX_FMT_RGBA = 28,
    AV_PIX_FMT_ABGR = 29,
    AV_PIX_FMT_BGRA = 30,
    AV_PIX_FMT_YUV420P10LE = 66,
    AV_PIX_FMT_YUV420P10BE = 67,
    AV_PIX_FMT_NV16 = 113
};

/* Sample formats */
enum AVSampleFormat {
    AV_SAMPLE_FMT_NONE = 0xffffffff,
    AV_SAMPLE_FMT_U8 = 0,
    AV_SAMPLE_FMT_S16 = 1,
    AV_SAMPLE_FMT_S32 = 2,
    AV_SAMPLE_FMT_FLT = 3,
    AV_SAMPLE_FMT_DBL = 4,
    AV_SAMPLE_FMT_U8P = 5,
    AV_SAMPLE_FMT_S16P = 6,
    AV_SAMPLE_FMT_S32P = 7,
    AV_SAMPLE_FMT_FLTP = 8,
    AV_SAMPLE_FMT_DBLP = 9,
    AV_SAMPLE_FMT_S64 = 10,
    AV_SAMPLE_FMT_S64P = 11
};

/* Media types */
enum AVMediaType {
    AVMEDIA_TYPE_UNKNOWN = 0xffffffff,
    AVMEDIA_TYPE_VIDEO = 0,
    AVMEDIA_TYPE_AUDIO = 1,
    AVMEDIA_TYPE_DATA = 2,
    AVMEDIA_TYPE_SUBTITLE = 3,
    AVMEDIA_TYPE_ATTACHMENT = 4
};

/* Error codes (negated POSIX errors with AVERROR tag) */
enum AVError {
    AVERROR_BSF_NOT_FOUND = 0xb9acbd08,
    AVERROR_BUG = 0xdeb8aabe,
    AVERROR_BUFFER_TOO_SMALL = 0xacb9aabe,
    AVERROR_DECODER_NOT_FOUND = 0xbcbabb9b,
    AVERROR_DEMUXER_NOT_FOUND = 0xb2babb9b,
    AVERROR_ENCODER_NOT_FOUND = 0xbcb1ba9b,
    AVERROR_EOF = 0xdfb9b0bb,
    AVERROR_EXIT = 0xabb6a7bb,
    AVERROR_EXTERNAL = 0xbebbb1bb,
    AVERROR_FILTER_NOT_FOUND = 0xb3b6b1bb,
    AVERROR_INVALIDDATA = 0xbebbb1bb,
    AVERROR_MUXER_NOT_FOUND = 0xa7aab2bb,
    AVERROR_OPTION_NOT_FOUND = 0xabafb6bb,
    AVERROR_PATCHWELCOME = 0xbaa8bebb,
    AVERROR_PROTOCOL_NOT_FOUND = 0xb0adaf9b,
    AVERROR_STREAM_NOT_FOUND = 0xadabacbb,
    AVERROR_BUG2 = 0xdfb8aabe,
    AVERROR_UNKNOWN = 0xb1b4b1ab
};

/* Log levels */
enum AVLogLevel {
    AV_LOG_QUIET = 0xfffffff8,
    AV_LOG_PANIC = 0,
    AV_LOG_FATAL = 8,
    AV_LOG_ERROR = 16,
    AV_LOG_WARNING = 24,
    AV_LOG_INFO = 32,
    AV_LOG_VERBOSE = 40,
    AV_LOG_DEBUG = 48,
    AV_LOG_TRACE = 56
};

/* Channel layout (common ones) */
enum AVChannelLayout {
    AV_CH_FRONT_LEFT = 0x00000001,
    AV_CH_FRONT_RIGHT = 0x00000002,
    AV_CH_FRONT_CENTER = 0x00000004,
    AV_CH_LOW_FREQUENCY = 0x00000008,
    AV_CH_BACK_LEFT = 0x00000010,
    AV_CH_BACK_RIGHT = 0x00000020,
    AV_CH_SIDE_LEFT = 0x00000200,
    AV_CH_SIDE_RIGHT = 0x00000400,
    AV_CH_LAYOUT_MONO = 0x00000004,
    AV_CH_LAYOUT_STEREO = 0x00000003,
    AV_CH_LAYOUT_SURROUND = 0x00000007,
    AV_CH_LAYOUT_5POINT1 = 0x0000003f
};

/* Rational number */
struct AVRational {
    int32_t num;    /* numerator */
    int32_t den;    /* denominator */
};

/* Buffer reference */
struct AVBufferRef {
    void *buffer;       /* AVBuffer pointer */
    void *data;         /* data buffer */
    uint64_t size;      /* size in bytes */
};

/* Dictionary */
struct AVDictionary {
    int32_t count;      /* number of entries */
    void *elems;        /* AVDictionaryEntry array */
};

/* Dictionary entry */
struct AVDictionaryEntry {
    char *key;
    char *value;
};

/* Frame structure (simplified) */
struct AVFrame {
    void *data[8];              /* pointers to picture/channel planes */
    int32_t linesize[8];        /* size in bytes of each plane line */
    void *extended_data;        /* pointers to data planes */
    int32_t width;              /* video width */
    int32_t height;             /* video height */
    int32_t nb_samples;         /* audio samples per channel */
    int32_t format;             /* pixel/sample format */
    int32_t key_frame;          /* 1 if keyframe */
    int32_t pict_type;          /* picture type */
    struct AVRational sample_aspect_ratio;
    int64_t pts;                /* presentation timestamp */
    int64_t pkt_dts;            /* decompression timestamp */
    struct AVRational time_base;
    int32_t quality;            /* quality (1=best, FF_LAMBDA_MAX=worst) */
    void *opaque;               /* user private data */
    int32_t repeat_pict;        /* extra pictures to display */
    int32_t interlaced_frame;   /* 1 if interlaced */
    int32_t top_field_first;    /* top field displayed first */
    int32_t palette_has_changed;
    int64_t reordered_opaque;
    int32_t sample_rate;        /* audio sample rate */
    uint64_t channel_layout;    /* audio channel layout bitmask */
    void *buf[8];               /* AVBufferRef pointers */
    void *extended_buf;         /* additional AVBufferRef array */
    int32_t nb_extended_buf;
    void *side_data;            /* AVFrameSideData array */
    int32_t nb_side_data;
    int32_t flags;
    int32_t color_range;
    int32_t color_primaries;
    int32_t color_trc;
    int32_t colorspace;
    int32_t chroma_location;
    int64_t best_effort_timestamp;
    int64_t pkt_pos;            /* byte position in stream */
    int64_t pkt_duration;
    void *metadata;             /* AVDictionary pointer */
    int32_t decode_error_flags;
    int32_t channels;           /* number of audio channels */
    int64_t pkt_size;           /* packet size */
    void *hw_frames_ctx;        /* AVBufferRef to AVHWFramesContext */
    void *opaque_ref;           /* AVBufferRef for user data */
    uint64_t crop_top;
    uint64_t crop_bottom;
    uint64_t crop_left;
    uint64_t crop_right;
    void *private_ref;
};

/* Class for logging and options */
struct AVClass {
    char *class_name;
    void *item_name;        /* function pointer */
    void *option;           /* AVOption array */
    int32_t version;
    int32_t log_level_offset_offset;
    int32_t parent_log_context_offset;
    void *child_next;       /* function pointer */
    void *child_class_next; /* function pointer */
    int32_t category;
    void *get_category;     /* function pointer */
    void *query_ranges;     /* function pointer */
};

/* Function signatures */

/* Memory allocation */
void *av_malloc(uint64_t size);
void *av_mallocz(uint64_t size);
void *av_calloc(uint64_t nmemb, uint64_t size);
void *av_realloc(void *ptr, uint64_t size);
void av_free(void *ptr);
void av_freep(void *ptr);
char *av_strdup(char *s);
void *av_memdup(void *p, uint64_t size);

/* Frame handling */
void *av_frame_alloc(void);
void av_frame_free(void **frame);
void *av_frame_clone(void *src);
int av_frame_ref(void *dst, void *src);
void av_frame_unref(void *frame);
int av_frame_copy(void *dst, void *src);
int av_frame_copy_props(void *dst, void *src);
int av_frame_get_buffer(void *frame, int align);
int av_frame_make_writable(void *frame);

/* Dictionary functions */
int av_dict_set(void **pm, char *key, char *value, int flags);
int av_dict_get(void *m, char *key, void *prev, int flags);
void av_dict_free(void **m);
int av_dict_copy(void **dst, void *src, int flags);
int av_dict_count(void *m);

/* Logging */
void av_log(void *avcl, int level, char *fmt);
void av_log_set_level(int level);
int av_log_get_level(void);

/* Error handling */
int av_strerror(int errnum, char *errbuf, uint64_t errbuf_size);

/* Parsing */
int av_parse_ratio(struct AVRational *q, char *str, int max, int log_offset, void *log_ctx);
int av_parse_time(int64_t *timeval, char *timestr, int duration);

/* Image functions */
int av_image_alloc(void *pointers, int *linesizes, int w, int h, int pix_fmt, int align);
int av_image_get_buffer_size(int pix_fmt, int width, int height, int align);
int av_image_copy_to_buffer(void *dst, int dst_size, void *src_data, int *src_linesize, int pix_fmt, int width, int height, int align);
int av_image_fill_arrays(void *dst_data, int *dst_linesize, void *src, int pix_fmt, int width, int height, int align);

/* Sample functions */
int av_samples_alloc(void *audio_data, int *linesize, int nb_channels, int nb_samples, int sample_fmt, int align);
int av_samples_get_buffer_size(int *linesize, int nb_channels, int nb_samples, int sample_fmt, int align);
int av_samples_fill_arrays(void *audio_data, int *linesize, void *buf, int nb_channels, int nb_samples, int sample_fmt, int align);

/* Math */
int64_t av_rescale(int64_t a, int64_t b, int64_t c);
int64_t av_rescale_rnd(int64_t a, int64_t b, int64_t c, int rnd);
int64_t av_rescale_q(int64_t a, struct AVRational bq, struct AVRational cq);
int64_t av_rescale_q_rnd(int64_t a, struct AVRational bq, struct AVRational cq, int rnd);

/* Base64 */
int av_base64_decode(void *out, char *in, int out_size);
char *av_base64_encode(char *out, int out_size, void *in, int in_size);

#endif /* FFMPEG_AVUTIL_TYPES_H */
