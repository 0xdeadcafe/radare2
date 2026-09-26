/* zlib type definitions for radare2 */
/* Load in r2: to types/zlib/zlib.h */

#ifndef ZLIB_TYPES_H
#define ZLIB_TYPES_H

/* zlib flush values */
enum zlib_flush {
    Z_NO_FLUSH = 0,
    Z_PARTIAL_FLUSH = 1,
    Z_SYNC_FLUSH = 2,
    Z_FULL_FLUSH = 3,
    Z_FINISH = 4,
    Z_BLOCK = 5,
    Z_TREES = 6
};

/* zlib return codes */
enum zlib_error {
    Z_OK = 0,
    Z_STREAM_END = 1,
    Z_NEED_DICT = 2,
    Z_ERRNO = 0xffffffff,
    Z_STREAM_ERROR = 0xfffffffe,
    Z_DATA_ERROR = 0xfffffffd,
    Z_MEM_ERROR = 0xfffffffc,
    Z_BUF_ERROR = 0xfffffffb,
    Z_VERSION_ERROR = 0xfffffffa
};

/* zlib compression levels */
enum zlib_level {
    Z_NO_COMPRESSION = 0,
    Z_BEST_SPEED = 1,
    Z_BEST_COMPRESSION = 9,
    Z_DEFAULT_COMPRESSION = 0xffffffff
};

/* zlib compression strategies */
enum zlib_strategy {
    Z_DEFAULT_STRATEGY = 0,
    Z_FILTERED = 1,
    Z_HUFFMAN_ONLY = 2,
    Z_RLE = 3,
    Z_FIXED = 4
};

/* zlib data types */
enum zlib_data_type {
    Z_BINARY = 0,
    Z_TEXT = 1,
    Z_ASCII = 1,
    Z_UNKNOWN = 2
};

/* z_stream structure - main compression/decompression state */
struct z_stream {
    void *next_in;          /* next input byte */
    uint32_t avail_in;      /* number of bytes available at next_in */
    uint64_t total_in;      /* total number of input bytes read so far */
    void *next_out;         /* next output byte will go here */
    uint32_t avail_out;     /* remaining free space at next_out */
    uint64_t total_out;     /* total number of bytes output so far */
    char *msg;              /* last error message, NULL if no error */
    void *state;            /* internal state, not visible by applications */
    void *zalloc;           /* alloc function pointer */
    void *zfree;            /* free function pointer */
    void *opaque;           /* private data passed to zalloc and zfree */
    int32_t data_type;      /* best guess about data type: binary or text */
    uint64_t adler;         /* Adler-32 or CRC-32 value */
    uint64_t reserved;      /* reserved for future use */
};

/* gz_header structure - gzip header information */
struct gz_header {
    int32_t text;           /* true if compressed data believed to be text */
    uint64_t time;          /* modification time */
    int32_t xflags;         /* extra flags */
    int32_t os;             /* operating system */
    void *extra;            /* pointer to extra field or NULL */
    uint32_t extra_len;     /* extra field length */
    uint32_t extra_max;     /* space at extra */
    void *name;             /* pointer to file name or NULL */
    uint32_t name_max;      /* space at name */
    void *comment;          /* pointer to comment or NULL */
    uint32_t comm_max;      /* space at comment */
    int32_t hcrc;           /* true if header crc present */
    int32_t done;           /* true when done reading gzip header */
};

/* Function signatures */

/* Basic functions */
int deflateInit(struct z_stream *strm, int level);
int deflate(struct z_stream *strm, int flush);
int deflateEnd(struct z_stream *strm);

int inflateInit(struct z_stream *strm);
int inflate(struct z_stream *strm, int flush);
int inflateEnd(struct z_stream *strm);

/* Advanced functions */
int deflateInit2(struct z_stream *strm, int level, int method, int windowBits, int memLevel, int strategy);
int deflateSetDictionary(struct z_stream *strm, void *dictionary, uint32_t dictLength);
int deflateReset(struct z_stream *strm);
int deflateParams(struct z_stream *strm, int level, int strategy);
int deflateBound(struct z_stream *strm, uint64_t sourceLen);
int deflateCopy(struct z_stream *dest, struct z_stream *source);

int inflateInit2(struct z_stream *strm, int windowBits);
int inflateSetDictionary(struct z_stream *strm, void *dictionary, uint32_t dictLength);
int inflateSync(struct z_stream *strm);
int inflateReset(struct z_stream *strm);
int inflateReset2(struct z_stream *strm, int windowBits);
int inflateCopy(struct z_stream *dest, struct z_stream *source);
int inflateGetHeader(struct z_stream *strm, struct gz_header *head);

/* Utility functions */
int compress(void *dest, uint64_t *destLen, void *source, uint64_t sourceLen);
int compress2(void *dest, uint64_t *destLen, void *source, uint64_t sourceLen, int level);
uint64_t compressBound(uint64_t sourceLen);
int uncompress(void *dest, uint64_t *destLen, void *source, uint64_t sourceLen);
int uncompress2(void *dest, uint64_t *destLen, void *source, uint64_t *sourceLen);

/* Checksum functions */
uint64_t adler32(uint64_t adler, void *buf, uint32_t len);
uint64_t adler32_z(uint64_t adler, void *buf, uint64_t len);
uint64_t adler32_combine(uint64_t adler1, uint64_t adler2, int64_t len2);
uint64_t crc32(uint64_t crc, void *buf, uint32_t len);
uint64_t crc32_z(uint64_t crc, void *buf, uint64_t len);
uint64_t crc32_combine(uint64_t crc1, uint64_t crc2, int64_t len2);

/* gzip file functions */
void *gzopen(char *path, char *mode);
void *gzdopen(int fd, char *mode);
int gzsetparams(void *file, int level, int strategy);
int gzread(void *file, void *buf, uint32_t len);
int64_t gzfread(void *buf, uint64_t size, uint64_t nitems, void *file);
int gzwrite(void *file, void *buf, uint32_t len);
int64_t gzfwrite(void *buf, uint64_t size, uint64_t nitems, void *file);
int gzprintf(void *file, char *format);
int gzputs(void *file, char *s);
char *gzgets(void *file, char *buf, int len);
int gzputc(void *file, int c);
int gzgetc(void *file);
int gzungetc(int c, void *file);
int gzflush(void *file, int flush);
int64_t gzseek(void *file, int64_t offset, int whence);
int gzrewind(void *file);
int64_t gztell(void *file);
int64_t gzoffset(void *file);
int gzeof(void *file);
int gzdirect(void *file);
int gzclose(void *file);
int gzclose_r(void *file);
int gzclose_w(void *file);
char *gzerror(void *file, int *errnum);
void gzclearerr(void *file);

/* Version */
char *zlibVersion(void);
uint64_t zlibCompileFlags(void);

#endif /* ZLIB_TYPES_H */
