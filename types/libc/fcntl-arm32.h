/*
 * Linux file and time structures for radare2 -- ARM32 (armhf / armeabi)
 *
 * Use this file for ARM32 LE targets (Cortex-A, ARM9, ARM926):
 *   to libc/fcntl-arm32.h
 *
 * Do NOT use types/libc/fcntl.h on ARM32: that file has x86_64 struct stat
 * (64-bit long, different field sizes) which gives wrong annotations on ARM32.
 *
 * Key differences from x86_64 stat:
 *   - long is 32 bits on ARM32 (not 64)
 *   - st_dev / st_rdev / st_ino / st_size / st_blocks are 64-bit via long long
 *   - Padding fields differ significantly
 *   - Total size: ~120 bytes vs x86_64's 144 bytes
 *
 * Sources:
 *   musl/arch/arm/bits/stat.h, linux/arch/arm/include/asm/stat.h,
 *   glibc sysdeps/unix/sysv/linux/arm/bits/stat.h
 */

/* Open flags -- same values as x86_64 on ARM32 */
enum linux_open_flags {
    O_RDONLY = 0,
    O_WRONLY = 1,
    O_RDWR = 2,
    O_CREAT = 64,
    O_EXCL = 128,
    O_NOCTTY = 256,
    O_TRUNC = 512,
    O_APPEND = 1024,
    O_NONBLOCK = 2048,
    O_DSYNC = 4096,
    O_SYNC = 1052672,
    O_DIRECTORY = 65536,
    O_NOFOLLOW = 131072,
    O_CLOEXEC = 524288,
    O_ASYNC = 8192,
    O_DIRECT = 16384,
    O_NOATIME = 262144,
    O_PATH = 2097152,
    O_TMPFILE = 4259840
};

/* File mode bits -- same across all architectures */
enum linux_mode {
    S_IFMT = 61440,
    S_IFSOCK = 49152,
    S_IFLNK = 40960,
    S_IFREG = 32768,
    S_IFBLK = 24576,
    S_IFDIR = 16384,
    S_IFCHR = 8192,
    S_IFIFO = 4096,
    S_ISUID = 2048,
    S_ISGID = 1024,
    S_ISVTX = 512,
    S_IRWXU = 448,
    S_IRUSR = 256,
    S_IWUSR = 128,
    S_IXUSR = 64,
    S_IRWXG = 56,
    S_IRGRP = 32,
    S_IWGRP = 16,
    S_IXGRP = 8,
    S_IRWXO = 7,
    S_IROTH = 4,
    S_IWOTH = 2,
    S_IXOTH = 1
};

/* Seek whence */
enum linux_seek {
    SEEK_SET = 0,
    SEEK_CUR = 1,
    SEEK_END = 2,
    SEEK_DATA = 3,
    SEEK_HOLE = 4
};

/* fcntl commands */
enum linux_fcntl_cmd {
    F_DUPFD = 0,
    F_GETFD = 1,
    F_SETFD = 2,
    F_GETFL = 3,
    F_SETFL = 4,
    F_GETLK = 5,
    F_SETLK = 6,
    F_SETLKW = 7,
    F_SETOWN = 8,
    F_GETOWN = 9,
    F_SETSIG = 10,
    F_GETSIG = 11,
    F_DUPFD_CLOEXEC = 1030
};

/* Access mode flags */
enum linux_access {
    F_OK = 0,
    X_OK = 1,
    W_OK = 2,
    R_OK = 4
};

/* mmap protection flags */
enum linux_prot {
    PROT_NONE = 0,
    PROT_READ = 1,
    PROT_WRITE = 2,
    PROT_EXEC = 4,
    PROT_GROWSDOWN = 16777216,
    PROT_GROWSUP = 33554432
};

/* mmap flags */
enum linux_map {
    MAP_SHARED = 1,
    MAP_PRIVATE = 2,
    MAP_FIXED = 16,
    MAP_ANONYMOUS = 32,
    MAP_GROWSDOWN = 256,
    MAP_DENYWRITE = 2048,
    MAP_EXECUTABLE = 4096,
    MAP_LOCKED = 8192,
    MAP_NORESERVE = 16384,
    MAP_POPULATE = 32768,
    MAP_NONBLOCK = 65536,
    MAP_STACK = 131072,
    MAP_HUGETLB = 262144
};

/* Time structures -- use int (32-bit) for long on ARM32 */
struct timeval {
    int tv_sec;
    int tv_usec;
};

struct timespec {
    int tv_sec;
    int tv_nsec;
};

/*
 * stat structure for ARM32 Linux (glibc armhf / musl arm)
 *
 * On ARM32, long is 32 bits. The stat struct uses 64-bit fields for dev/ino/size
 * via long long, with padding fields to maintain alignment.
 *
 * Layout (120 bytes total):
 *   [  0] long long st_dev      8 bytes
 *   [  8] int __pad0[3]        12 bytes (3 x 4)
 *   [ 20] int __st_ino          4 bytes (legacy 32-bit inode, for compat)
 *   [ 24] int st_mode           4 bytes
 *   [ 28] int st_nlink          4 bytes
 *   [ 32] int st_uid            4 bytes
 *   [ 36] int st_gid            4 bytes
 *   [ 40] long long st_rdev     8 bytes
 *   [ 48] int __pad1[3]        12 bytes
 *   [ 60] long long st_size     8 bytes
 *   [ 68] int st_blksize        4 bytes
 *   [ 72] int __pad2            4 bytes
 *   [ 76] long long st_blocks   8 bytes
 *   [ 84] int st_atime          4 bytes
 *   [ 88] int st_atime_nsec     4 bytes
 *   [ 92] int st_mtime          4 bytes
 *   [ 96] int st_mtime_nsec     4 bytes
 *   [100] int st_ctime          4 bytes
 *   [104] int st_ctime_nsec     4 bytes
 *   [108] long long st_ino      8 bytes (real 64-bit inode)
 *   [116] int __unused[1]       4 bytes
 */
struct stat {
    long long st_dev;
    int __pad0[3];
    int __st_ino;
    int st_mode;
    int st_nlink;
    int st_uid;
    int st_gid;
    long long st_rdev;
    int __pad1[3];
    long long st_size;
    int st_blksize;
    int __pad2;
    long long st_blocks;
    int st_atime;
    int st_atime_nsec;
    int st_mtime;
    int st_mtime_nsec;
    int st_ctime;
    int st_ctime_nsec;
    long long st_ino;
    int __unused;
};

/*
 * Directory entry for ARM32 Linux
 * (d_ino is 64-bit, d_off is 64-bit in modern kernels)
 */
struct dirent {
    long long d_ino;
    long long d_off;
    short d_reclen;
    char d_type;
    char d_name[256];
};

/* File types in dirent */
enum linux_dtype {
    DT_UNKNOWN = 0,
    DT_FIFO = 1,
    DT_CHR = 2,
    DT_DIR = 4,
    DT_BLK = 6,
    DT_REG = 8,
    DT_LNK = 10,
    DT_SOCK = 12,
    DT_WHT = 14
};

/* File operations */
int open(char *pathname, int flags, int mode);
int openat(int dirfd, char *pathname, int flags, int mode);
int creat(char *pathname, int mode);
int fcntl(int fd, int cmd, int arg);
int close(int fd);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int read(int fd, void *buf, int count);
int write(int fd, void *buf, int count);
int pread(int fd, void *buf, int count, long long offset);
int pwrite(int fd, void *buf, int count, long long offset);
long long lseek(int fd, long long offset, int whence);
int access(char *pathname, int mode);
int faccessat(int dirfd, char *pathname, int mode, int flags);
int unlink(char *pathname);
int rename(char *oldpath, char *newpath);
int mkdir(char *pathname, int mode);
int rmdir(char *pathname);
int chmod(char *pathname, int mode);
int pipe(int pipefd[2]);
int pipe2(int pipefd[2], int flags);
