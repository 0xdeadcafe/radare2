/* FFmpeg libavformat type definitions for radare2 */
/* Load in r2: to types/ffmpeg/avformat.h */

#ifndef FFMPEG_AVFORMAT_TYPES_H
#define FFMPEG_AVFORMAT_TYPES_H

/* Format flags */
enum AVFormatFlag {
    AVFMT_NOFILE = 0x0001,
    AVFMT_NEEDNUMBER = 0x0002,
    AVFMT_SHOW_IDS = 0x0008,
    AVFMT_GLOBALHEADER = 0x0040,
    AVFMT_NOTIMESTAMPS = 0x0080,
    AVFMT_GENERIC_INDEX = 0x0100,
    AVFMT_TS_DISCONT = 0x0200,
    AVFMT_VARIABLE_FPS = 0x0400,
    AVFMT_NODIMENSIONS = 0x0800,
    AVFMT_NOSTREAMS = 0x1000,
    AVFMT_NOBINSEARCH = 0x2000,
    AVFMT_NOGENSEARCH = 0x4000,
    AVFMT_NO_BYTE_SEEK = 0x8000,
    AVFMT_ALLOW_FLUSH = 0x10000,
    AVFMT_TS_NONSTRICT = 0x20000,
    AVFMT_TS_NEGATIVE = 0x40000,
    AVFMT_SEEK_TO_PTS = 0x4000000
};

/* AVIO flags */
enum AVIOFlag {
    AVIO_FLAG_READ = 1,
    AVIO_FLAG_WRITE = 2,
    AVIO_FLAG_READ_WRITE = 3,
    AVIO_FLAG_NONBLOCK = 8,
    AVIO_FLAG_DIRECT = 0x8000
};

/* Seek flags */
enum AVSeekFlag {
    AVSEEK_FLAG_BACKWARD = 1,
    AVSEEK_FLAG_BYTE = 2,
    AVSEEK_FLAG_ANY = 4,
    AVSEEK_FLAG_FRAME = 8
};

/* Duration estimation methods */
enum AVDurationEstimationMethod {
    AVFMT_DURATION_FROM_PTS = 0,
    AVFMT_DURATION_FROM_STREAM = 1,
    AVFMT_DURATION_FROM_BITRATE = 2
};

/* Stream disposition flags */
enum AVDisposition {
    AV_DISPOSITION_DEFAULT = 0x0001,
    AV_DISPOSITION_DUB = 0x0002,
    AV_DISPOSITION_ORIGINAL = 0x0004,
    AV_DISPOSITION_COMMENT = 0x0008,
    AV_DISPOSITION_LYRICS = 0x0010,
    AV_DISPOSITION_KARAOKE = 0x0020,
    AV_DISPOSITION_FORCED = 0x0040,
    AV_DISPOSITION_HEARING_IMPAIRED = 0x0080,
    AV_DISPOSITION_VISUAL_IMPAIRED = 0x0100,
    AV_DISPOSITION_CLEAN_EFFECTS = 0x0200,
    AV_DISPOSITION_ATTACHED_PIC = 0x0400,
    AV_DISPOSITION_CAPTIONS = 0x10000,
    AV_DISPOSITION_DESCRIPTIONS = 0x20000,
    AV_DISPOSITION_METADATA = 0x40000
};

/* IO context */
struct AVIOContext {
    void *av_class;         /* AVClass pointer */
    void *buffer;           /* buffer start */
    int32_t buffer_size;
    void *buf_ptr;          /* current position */
    void *buf_end;          /* end of data */
    void *opaque;           /* user private data */
    void *read_packet;      /* callback */
    void *write_packet;     /* callback */
    void *seek;             /* callback */
    int64_t pos;            /* position in file */
    int32_t eof_reached;
    int32_t write_flag;
    int32_t max_packet_size;
    int64_t checksum;
    void *checksum_ptr;
    void *update_checksum;  /* callback */
    int32_t error;
    void *read_pause;       /* callback */
    void *read_seek;        /* callback */
    int32_t seekable;
    int64_t maxsize;
    int32_t direct;
    int64_t bytes_read;
    int32_t seek_count;
    int32_t writeout_count;
    int32_t orig_buffer_size;
    int32_t short_seek_threshold;
    char *protocol_whitelist;
    char *protocol_blacklist;
    void *write_data_type;  /* callback */
    int32_t ignore_boundary_point;
    void *buf_ptr_max;
    int64_t min_packet_size;
};

/* Input format */
struct AVInputFormat {
    char *name;
    char *long_name;
    int32_t flags;
    char *extensions;
    void *codec_tag;
    void *priv_class;       /* AVClass pointer */
    char *mime_type;
    /* Private fields follow */
};

/* Output format */
struct AVOutputFormat {
    char *name;
    char *long_name;
    char *mime_type;
    char *extensions;
    int32_t audio_codec;    /* AVCodecID */
    int32_t video_codec;    /* AVCodecID */
    int32_t subtitle_codec; /* AVCodecID */
    int32_t flags;
    void *codec_tag;
    void *priv_class;       /* AVClass pointer */
    /* Private fields follow */
};

/* Stream structure */
struct AVStream {
    int32_t index;
    int32_t id;
    void *codecpar;         /* AVCodecParameters pointer */
    void *priv_data;
    struct AVRational time_base;
    int64_t start_time;
    int64_t duration;
    int64_t nb_frames;
    int32_t disposition;
    int32_t discard;        /* AVDiscard */
    struct AVRational sample_aspect_ratio;
    void *metadata;         /* AVDictionary pointer */
    struct AVRational avg_frame_rate;
    struct AVPacket attached_pic;
    void *side_data;
    int32_t nb_side_data;
    int32_t event_flags;
    struct AVRational r_frame_rate;
    int32_t pts_wrap_bits;
};

/* Format context */
struct AVFormatContext {
    void *av_class;         /* AVClass pointer */
    void *iformat;          /* AVInputFormat pointer */
    void *oformat;          /* AVOutputFormat pointer */
    void *priv_data;
    void *pb;               /* AVIOContext pointer */
    int32_t ctx_flags;
    uint32_t nb_streams;
    void **streams;         /* AVStream pointer array */
    char *url;
    int64_t start_time;
    int64_t duration;
    int64_t bit_rate;
    uint32_t packet_size;
    int32_t max_delay;
    int32_t flags;
    int64_t probesize;
    int64_t max_analyze_duration;
    void *key;
    int32_t keylen;
    uint32_t nb_programs;
    void **programs;        /* AVProgram pointer array */
    int32_t video_codec_id; /* AVCodecID */
    int32_t audio_codec_id; /* AVCodecID */
    int32_t subtitle_codec_id; /* AVCodecID */
    uint32_t max_index_size;
    uint32_t max_picture_buffer;
    uint32_t nb_chapters;
    void **chapters;        /* AVChapter pointer array */
    void *metadata;         /* AVDictionary pointer */
    int64_t start_time_realtime;
    int32_t fps_probe_size;
    int32_t error_recognition;
    struct AVIOInterruptCB interrupt_callback;
    int32_t debug;
    int64_t max_interleave_delta;
    int32_t strict_std_compliance;
    int32_t event_flags;
    int32_t max_ts_probe;
    int32_t avoid_negative_ts;
    int32_t ts_id;
    int32_t audio_preload;
    int32_t max_chunk_duration;
    int32_t max_chunk_size;
    int32_t use_wallclock_as_timestamps;
    int32_t avio_flags;
    int32_t duration_estimation_method;
    int64_t skip_initial_bytes;
    uint32_t correct_ts_overflow;
    int32_t seek2any;
    int32_t flush_packets;
    int32_t probe_score;
    int32_t format_probesize;
    char *codec_whitelist;
    char *format_whitelist;
    void *internal;
    int32_t io_repositioned;
    void *video_codec;      /* AVCodec pointer */
    void *audio_codec;      /* AVCodec pointer */
    void *subtitle_codec;   /* AVCodec pointer */
    void *data_codec;       /* AVCodec pointer */
    int32_t metadata_header_padding;
    void *opaque;
    void *control_message_cb;
    int64_t output_ts_offset;
    void *dump_separator;
    int32_t data_codec_id;  /* AVCodecID */
    char *protocol_whitelist;
    void *io_open;          /* callback */
    void *io_close;         /* callback */
    char *protocol_blacklist;
    int32_t max_streams;
    int32_t skip_estimate_duration_from_pts;
    int32_t max_probe_packets;
};

/* Interrupt callback */
struct AVIOInterruptCB {
    void *callback;
    void *opaque;
};

/* Function signatures */

/* Registration (deprecated in newer versions) */
void av_register_all(void);
void avformat_network_init(void);
void avformat_network_deinit(void);

/* Input */
int avformat_open_input(void **ps, char *url, void *fmt, void **options);
int avformat_find_stream_info(void *ic, void **options);
int av_find_best_stream(void *ic, int type, int wanted_stream_nb, int related_stream, void **decoder_ret, int flags);
int av_read_frame(void *s, void *pkt);
int av_seek_frame(void *s, int stream_index, int64_t timestamp, int flags);
int avformat_seek_file(void *s, int stream_index, int64_t min_ts, int64_t ts, int64_t max_ts, int flags);
void avformat_close_input(void **s);

/* Output */
void *avformat_alloc_output_context2(void **ctx, void *oformat, char *format_name, char *filename);
void *avformat_new_stream(void *s, void *c);
int avformat_write_header(void *s, void **options);
int av_write_frame(void *s, void *pkt);
int av_interleaved_write_frame(void *s, void *pkt);
int av_write_trailer(void *s);

/* Context */
void *avformat_alloc_context(void);
void avformat_free_context(void *s);

/* Format iteration */
void *av_demuxer_iterate(void **opaque);
void *av_muxer_iterate(void **opaque);
void *av_find_input_format(char *short_name);
void *av_guess_format(char *short_name, char *filename, char *mime_type);

/* IO */
int avio_open(void **s, char *url, int flags);
int avio_open2(void **s, char *url, int flags, void *int_cb, void **options);
int avio_close(void *s);
int avio_read(void *s, void *buf, int size);
void avio_write(void *s, void *buf, int size);
int64_t avio_seek(void *s, int64_t offset, int whence);
int64_t avio_skip(void *s, int64_t offset);
int64_t avio_size(void *s);
int avio_feof(void *s);
void avio_flush(void *s);

/* Utility */
void av_dump_format(void *ic, int index, char *url, int is_output);
int64_t av_gettime(void);
int64_t av_gettime_relative(void);

/* Version/config */
uint32_t avformat_version(void);
char *avformat_configuration(void);
char *avformat_license(void);

#endif /* FFMPEG_AVFORMAT_TYPES_H */
