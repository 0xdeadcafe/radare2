/*
 * FreeBSD / BSD userland type definitions for radare2
 *
 * Covers FreeBSD 12.x / 13.x / 14.x (applicable to TrueNAS, OPNsense,
 * Juniper JunOS, pfSense, and other FreeBSD-based firmware).
 *
 * Usage:
 *   to freebsd/freebsd.h
 *   tf kqueue            # show kqueue signature
 *   tsc kevent           # show kevent struct
 *   te bsd_errno         # BSD-specific errno values
 *
 * Note: FreeBSD shares most POSIX APIs with Linux but has different
 * syscall numbers and some structural differences. Use libc/functions.h
 * alongside this file for full coverage.
 */

/* ============================================================================
 * BSD-specific errno codes (extends POSIX set)
 * These differ from Linux in the 80-100 range
 * ============================================================================ */

enum bsd_errno_ext {
    /* FreeBSD-specific or different from Linux */
    EPROCLIM   = 67,   /* Too many processes */
    EUSERS     = 68,   /* Too many users */
    ESTALE     = 70,   /* Stale NFS file handle */
    EREMOTE    = 71,   /* Too many levels of remote in path */
    EBADRPC    = 72,   /* RPC struct is bad */
    ERPCMISMATCH = 73, /* RPC version wrong */
    EPROGUNAVAIL = 74, /* RPC program not available */
    EPROGMISMATCH = 75,/* RPC program version wrong */
    EPROCUNAVAIL = 76, /* RPC bad procedure for program */
    ENOLCK     = 77,   /* No locks available */
    ENOSYS     = 78,   /* Function not implemented */
    EFTYPE     = 79,   /* Inappropriate file type or format */
    EAUTH      = 80,   /* Authentication error */
    ENEEDAUTH  = 81,   /* Need authenticator */
    EIDRM      = 82,   /* Identifier removed */
    ENOMSG     = 83,   /* No message of desired type */
    EOVERFLOW  = 84,   /* Value too large to be stored in data type */
    ECANCELED  = 85,   /* Operation canceled */
    EILSEQ     = 86,   /* Illegal byte sequence */
    ENOATTR    = 87,   /* Attribute not found */
    EDOOFUS    = 88,   /* Programming error */
    EBADMSG    = 89,   /* Bad message */
    EMULTIHOP  = 90,   /* Multihop attempted */
    ENOLINK    = 91,   /* Link has been severed */
    EPROTO     = 92,   /* Protocol error */
    ENOTCAPABLE = 93,  /* Capabilities insufficient (Capsicum) */
    ECAPMODE   = 94,   /* Not permitted in capability mode (Capsicum) */
    ENOTRECOVERABLE = 95,
    EOWNERDEAD = 96
};

/* ============================================================================
 * BSD socket options (SOL_SOCKET level, differ from Linux in some values)
 * ============================================================================ */

enum bsd_so_opt {
    SO_DEBUG       = 0x0001,
    SO_ACCEPTCONN  = 0x0002,
    SO_REUSEADDR   = 0x0004,
    SO_KEEPALIVE   = 0x0008,
    SO_DONTROUTE   = 0x0010,
    SO_BROADCAST   = 0x0020,
    SO_USELOOPBACK = 0x0040,
    SO_LINGER      = 0x0080,
    SO_OOBINLINE   = 0x0100,
    SO_REUSEPORT   = 0x0200,
    SO_TIMESTAMP   = 0x0400,
    SO_NOSIGPIPE   = 0x0800,
    SO_ACCEPTFILTER = 0x1000,
    SO_BINTIME     = 0x2000,
    SO_NO_OFFLOAD  = 0x4000,
    SO_NO_DDP      = 0x8000,
    SO_SNDBUF      = 0x1001,
    SO_RCVBUF      = 0x1002,
    SO_SNDLOWAT    = 0x1003,
    SO_RCVLOWAT    = 0x1004,
    SO_SNDTIMEO    = 0x1005,
    SO_RCVTIMEO    = 0x1006,
    SO_ERROR       = 0x1007,
    SO_TYPE        = 0x1008,
    SO_LABEL       = 0x1009,
    SO_PEERLABEL   = 0x1010,
    SO_LISTENQLIMIT = 0x1011,
    SO_LISTENQLEN  = 0x1012,
    SO_LISTENINCQLEN = 0x1013
};

/* ============================================================================
 * kqueue / kevent — BSD event notification interface
 * Used heavily in JunOS (kmd), pfSense, FreeBSD servers
 * ============================================================================ */

/* kevent filter types */
enum kevent_filter {
    EVFILT_READ     = -1,   /* socket/pipe/fifo readable */
    EVFILT_WRITE    = -2,   /* socket/pipe/fifo writable */
    EVFILT_AIO      = -3,   /* aio_read/aio_write completion */
    EVFILT_VNODE    = -4,   /* vnode change */
    EVFILT_PROC     = -5,   /* process event */
    EVFILT_SIGNAL   = -6,   /* signal delivered */
    EVFILT_TIMER    = -7,   /* periodic/one-shot timer */
    EVFILT_PROCDESC = -8,   /* process descriptor event */
    EVFILT_FS       = -9,   /* file system events */
    EVFILT_LIO      = -10,  /* lio_listio completion */
    EVFILT_USER     = -11,  /* user-defined event */
    EVFILT_SENDFILE = -12,  /* sendfile progress */
    EVFILT_EMPTY    = -13   /* socket send buffer empty */
};

/* kevent action flags */
enum kevent_flags {
    EV_ADD     = 0x0001,    /* add event to kq */
    EV_DELETE  = 0x0002,    /* delete event from kq */
    EV_ENABLE  = 0x0004,    /* enable disabled event */
    EV_DISABLE = 0x0008,    /* disable event, don't remove */
    EV_ONESHOT = 0x0010,    /* only report one occurrence */
    EV_CLEAR   = 0x0020,    /* clear event state after reporting */
    EV_RECEIPT = 0x0040,    /* force EV_ERROR on success, data=0 */
    EV_DISPATCH = 0x0080,   /* disable after triggering */
    EV_SYSFLAGS = 0xF000,
    EV_DROP    = 0x1000,
    EV_FLAG1   = 0x2000,
    EV_FLAG2   = 0x4000,
    EV_EOF     = 0x8000,    /* EOF detected */
    EV_ERROR   = 0x4000     /* error — data contains errno */
};

/* struct kevent — kqueue event descriptor */
struct kevent {
    long ident;         /* identifier for this event (fd, pid, signal) */
    short filter;       /* filter for event (EVFILT_*) */
    short flags;        /* action flags (EV_ADD, EV_DELETE, ...) */
    int fflags;         /* filter flag value */
    long data;          /* filter data value */
    void *udata;        /* opaque user data identifier */
};

/* ============================================================================
 * BSD-specific file operations
 * ============================================================================ */

int kqueue(void);
int kevent(int kq, struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, void *timeout);

/* BSD sendfile (different prototype from Linux) */
int sendfile(int fd, int s, long long offset, int nbytes, void *hdtr, void *sbytes, int flags);

/* BSD sysctl */
int sysctl(int *name, int namelen, void *oldp, void *oldlenp, void *newp, int newlen);
int sysctlbyname(char *name, void *oldp, void *oldlenp, void *newp, int newlen);
int sysctlnametomib(char *name, int *mibp, void *sizep);

/* BSD pthread extensions */
int pthread_set_name_np(void *tid, char *name);
int pthread_getthreadid_np(void);
int pthread_main_np(void);

/* BSD getpeereid (Unix domain socket peer credentials) */
int getpeereid(int s, void *euid, void *egid);

/* BSD-specific signal handling */
int sigwait(void *set, void *sig);
int sigtimedwait(void *set, void *info, void *timeout);
int sigwaitinfo(void *set, void *info);

/* BSD jail (isolation primitive) */
int jail(void *j);
int jail_attach(int jid);
int jail_remove(int jid);
int jail_get(void *iov, int niov, int flags);
int jail_set(void *iov, int niov, int flags);

/* Capsicum capability API (FreeBSD 10+) */
int cap_enter(void);
int cap_sandboxed(void);
int cap_rights_limit(int fd, void *rights);
int cap_rights_get(int fd, void *rights);
int cap_ioctls_limit(int fd, void *cmds, int ncmds);
int cap_fcntls_limit(int fd, int fcntlrights);

/* ============================================================================
 * BSD stat structure
 * FreeBSD stat is similar to x86_64 Linux but uses different types
 * ============================================================================ */

struct freebsd_stat {
    long long st_dev;        /* inode's device */
    int st_ino;              /* inode's number (32-bit on x86 FreeBSD) */
    short st_mode;           /* inode protection mode */
    short st_nlink;          /* number of hard links */
    int st_uid;              /* user ID of the file's owner */
    int st_gid;              /* group ID of the file's group */
    long long st_rdev;       /* device type */
    long st_atim_sec;        /* time of last access (seconds) */
    long st_atim_nsec;       /* time of last access (nanoseconds) */
    long st_mtim_sec;        /* time of last data modification (seconds) */
    long st_mtim_nsec;
    long st_ctim_sec;        /* time of last file status change (seconds) */
    long st_ctim_nsec;
    long long st_size;       /* file size in bytes */
    long long st_blocks;     /* blocks allocated for file */
    int st_blksize;          /* optimal blocksize for I/O */
    int st_flags;            /* user-defined flags for file */
    int st_gen;              /* file generation number */
    int st_lspare;
    long st_birthtim_sec;    /* file creation time (seconds) */
    long st_birthtim_nsec;
};
