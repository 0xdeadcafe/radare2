/*
 * Linux file and time structures for radare2
 *
 * Usage: to types/libc/fcntl.h
 *
 * Note: struct stat varies significantly by architecture
 * These definitions are for x86_64 Linux
 */

/* Open flags */
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
    O_RSYNC = 1052672,
    O_DIRECTORY = 65536,
    O_NOFOLLOW = 131072,
    O_CLOEXEC = 524288,
    O_ASYNC = 8192,
    O_DIRECT = 16384,
    O_LARGEFILE = 0,
    O_NOATIME = 262144,
    O_PATH = 2097152,
    O_TMPFILE = 4259840
};

/* File mode bits */
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

/* Time structures */
struct timeval {
    long tv_sec;
    long tv_usec;
};

struct timespec {
    long tv_sec;
    long tv_nsec;
};

/* stat structure - x86_64 Linux */
struct stat {
    long st_dev;
    long st_ino;
    long st_nlink;
    int st_mode;
    int st_uid;
    int st_gid;
    int __pad0;
    long st_rdev;
    long st_size;
    long st_blksize;
    long st_blocks;
    long st_atime;
    long st_atime_nsec;
    long st_mtime;
    long st_mtime_nsec;
    long st_ctime;
    long st_ctime_nsec;
    long __unused[3];
};

/* Directory entry */
struct dirent {
    long d_ino;
    long d_off;
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
int dup3(int oldfd, int newfd, int flags);
int read(int fd, void *buf, int count);
int write(int fd, void *buf, int count);
int pread(int fd, void *buf, int count, long offset);
int pwrite(int fd, void *buf, int count, long offset);
long lseek(int fd, long offset, int whence);
int access(char *pathname, int mode);
int faccessat(int dirfd, char *pathname, int mode, int flags);
int unlink(char *pathname);
int unlinkat(int dirfd, char *pathname, int flags);
int rename(char *oldpath, char *newpath);
int renameat(int olddirfd, char *oldpath, int newdirfd, char *newpath);
int mkdir(char *pathname, int mode);
int mkdirat(int dirfd, char *pathname, int mode);
int rmdir(char *pathname);
int chmod(char *pathname, int mode);
int fchmodat(int dirfd, char *pathname, int mode, int flags);
int posix_fadvise(int fd, long offset, long len, int advice);
int fallocate(int fd, int mode, long offset, long len);
int pipe(int pipefd[2]);
int pipe2(int pipefd[2], int flags);
