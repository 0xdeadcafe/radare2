# FFmpeg Type Definitions for radare2

Type definitions for the FFmpeg multimedia libraries.

## Files

| File | Contents |
|------|----------|
| `avutil.h` | AVFrame, AVRational, pixel/sample formats, memory functions |
| `avcodec.h` | AVCodec, AVCodecContext, AVPacket, codec IDs, decode/encode |
| `avformat.h` | AVFormatContext, AVStream, AVIOContext, muxing/demuxing |

## Usage

```r2
# Load FFmpeg types
to types/ffmpeg/avutil.h
to types/ffmpeg/avcodec.h
to types/ffmpeg/avformat.h

# Look up codec IDs
te AVCodecID

# Look up pixel formats
te AVPixelFormat

# Show AVFrame structure
ts AVFrame

# Show function signature
tfc avformat_open_input
tfc avcodec_send_packet

# Apply struct to memory
tp AVFormatContext @ rdi
tp AVPacket @ rsi
```

## Quick Reference

### Common Codec IDs
```
AV_CODEC_ID_H264 = 27
AV_CODEC_ID_HEVC = 173
AV_CODEC_ID_VP8 = 139
AV_CODEC_ID_VP9 = 167
AV_CODEC_ID_AV1 = 226
AV_CODEC_ID_AAC = 0x15002
AV_CODEC_ID_MP3 = 0x15001
AV_CODEC_ID_OPUS = 0x1503c
```

### Common Pixel Formats
```
AV_PIX_FMT_YUV420P = 0
AV_PIX_FMT_RGB24 = 2
AV_PIX_FMT_BGR24 = 3
AV_PIX_FMT_NV12 = 25
AV_PIX_FMT_RGBA = 28
AV_PIX_FMT_BGRA = 30
```

### Media Types
```
AVMEDIA_TYPE_VIDEO = 0
AVMEDIA_TYPE_AUDIO = 1
AVMEDIA_TYPE_DATA = 2
AVMEDIA_TYPE_SUBTITLE = 3
```

### Sample Formats
```
AV_SAMPLE_FMT_S16 = 1
AV_SAMPLE_FMT_S32 = 2
AV_SAMPLE_FMT_FLT = 3
AV_SAMPLE_FMT_FLTP = 8 (planar float)
```

## Common Analysis Patterns

### Track codec initialization
```r2
# Break on decoder lookup
db sym.avcodec_find_decoder
dc
# Check codec ID argument
dr rdi
te AVCodecID [rdi]
```

### Analyze packet processing
```r2
# Break on packet send
db sym.avcodec_send_packet
dc
# View packet structure
tp AVPacket @ rsi
pf qq pts dts @ rsi+8
```

### Find format detection
```r2
# Break on format open
db sym.avformat_open_input
dc
# View URL argument
ps @ rdx
```

## Combining with zsigs

```r2
# Load Debian amd64 FFmpeg signatures
zo zigns/debian/amd64/libavutil.zsig
zo zigns/debian/amd64/libavcodec.zsig
zo zigns/debian/amd64/libavformat.zsig

# Load type information
to types/ffmpeg/avutil.h
to types/ffmpeg/avcodec.h
to types/ffmpeg/avformat.h

# Analyze
aaa
z/              # Match signatures
```

## Architecture Notes

The struct definitions are for **64-bit Linux** with FFmpeg 5.x.
Field offsets may differ on:
- 32-bit systems (pointer sizes)
- Different FFmpeg versions (struct layout changes)
- Windows builds (different ABI)

FFmpeg structures evolve between major versions. These definitions
are based on FFmpeg 5.1 (Debian bookworm). For precise analysis,
verify against the specific FFmpeg version in your target binary.
