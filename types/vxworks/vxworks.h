/*
 * vxworks.h -- VxWorks 7 type definitions for radare2
 *
 * Platform: VxWorks 7 (Wind River RTOS) -- x86-64, ARM32, AArch64, MIPS
 * Common targets: maritime VSAT modems, avionics, industrial controllers,
 *                 network appliances (Icom AP-90M, JRC, Navico)
 *
 * Usage:
 *   to vxworks/vxworks.h
 *   aaft    # apply types to imports
 *
 * Load with profile: profiles/vxworks7-x86_64.r2
 *                    profiles/icom-vxworks-mips.r2
 *                    profiles/icom-ap90m-vxworks.r2
 *
 * Sources:
 *   - wrsdk-vxworks7-qemu-1.16.1 (VxWorks OS 25.09, x86-64)
 *   - vxworks-headers from WindRiver online docs
 *   - Analysis of Icom AP-90M, JRC JUE-100GX firmware
 */

#ifndef VXWORKS_H
#define VXWORKS_H

#include <stdint.h>
#include <stddef.h>

/* --- Basic VxWorks typedefs ------------------------------------------------- */

typedef int             STATUS;         /* OK=0, ERROR=-1 */
typedef int             BOOL;           /* TRUE=1, FALSE=0 */
typedef void *          FUNCPTR;        /* generic function pointer */
typedef unsigned int    UINT;
typedef unsigned long   ULONG;
typedef unsigned char   UCHAR;
typedef unsigned short  USHORT;

#define OK      0
#define ERROR   (-1)
#define TRUE    1
#define FALSE   0

/* --- Task / semaphore types ------------------------------------------------ */

typedef int     TASK_ID;        /* task identifier */
typedef void *  SEM_ID;         /* semaphore identifier */
typedef void *  MSG_Q_ID;       /* message queue identifier */
typedef void *  WD_ID;          /* watchdog timer identifier */

/* semaphore options (semCreate flags) */
enum vx_sem_opts {
    SEM_Q_FIFO          = 0x00,   /* queue tasks by arrival order */
    SEM_Q_PRIORITY      = 0x01,   /* queue tasks by priority */
    SEM_DELETE_SAFE     = 0x04,   /* protect against deletion */
    SEM_INVERSION_SAFE  = 0x08,   /* protect against priority inversion */
    SEM_EVENTSEND_ERR_NOTIFY = 0x10
};

/* task priority constants */
enum vx_task_prio {
    VX_PRIO_HIGH = 0,             /* highest (0 = most urgent) */
    VX_PRIO_LOW  = 255            /* lowest */
};

/* --- Error codes (errno) --------------------------------------------------- */

/* VxWorks errno values are POSIX + vendor-specific in the 0x3?xxxx range */
enum vx_errno {
    S_semLib_INVALID_STATE          = 0x00030065,
    S_msgQLib_INVALID_MSG_LENGTH    = 0x00030191,
    S_taskLib_ILLEGAL_PRIORITY      = 0x0003010f,
    S_ioLib_INVALID_FILE_DESCRIPTOR = 0x00030055,
    S_netLib_INVALID_ARGUMENT       = 0x00035201
};

/* --- Network (BSD socket compat) ------------------------------------------- */

/* VxWorks socket address family -- same as POSIX on most BSPs */
enum vx_af {
    AF_UNSPEC   = 0,
    AF_INET     = 2,
    AF_INET6    = 10,
    AF_UNIX     = 1
};

struct sockaddr_in {
    uint8_t  sin_len;         /* VxWorks adds sin_len at offset 0 (1 byte) */
    uint8_t  sin_family;      /* AF_INET = 2 */
    uint16_t sin_port;        /* port in network byte order */
    uint32_t sin_addr;        /* IPv4 address in network byte order */
    char     sin_zero[8];     /* padding */
};

struct sockaddr {
    uint8_t sa_len;
    uint8_t sa_family;
    char    sa_data[14];
};

/* --- I/O system ------------------------------------------------------------ */

/* VxWorks ioctl request codes */
enum vx_ioctl {
    FIONREAD    = 0x40046f01,   /* get number of bytes to read */
    FIONWRITE   = 0x40046f02,   /* get number of bytes pending write */
    FIOFLUSH    = 0x20006f03,   /* flush I/O */
    FIOSEEK     = 0x80086f04,   /* seek to offset */
    FIONBIO     = 0x40046f2e,   /* set non-blocking I/O */
    FIOGETNAME  = 0x00006f25    /* get name of fd */
};

/* --- VxWorks-specific kernel services ------------------------------------- */

/* taskSpawn() priority, options flags */
enum vx_task_options {
    VX_SUPERVISOR_MODE  = 0x0001,
    VX_UNBREAKABLE      = 0x0002,
    VX_DEALLOC_STACK    = 0x0004,
    VX_FP_TASK          = 0x0008,   /* floating-point capable */
    VX_PRIVATE_ENV      = 0x0080,
    VX_NO_STACK_FILL    = 0x0100
};

/* Task state values returned by taskInfoGet() */
enum vx_task_state {
    READY       = 0x00,
    PEND        = 0x01,
    DELAY       = 0x02,
    SUSPEND     = 0x04,
    STOP        = 0x08,
    DELAY_S     = 0x06,
    PEND_S      = 0x05
};

/* --- syslog / logLib ------------------------------------------------------- */

/* logMsg() priority levels */
enum vx_log_level {
    LOG_EMERG   = 0,
    LOG_ALERT   = 1,
    LOG_CRIT    = 2,
    LOG_ERR     = 3,
    LOG_WARNING = 4,
    LOG_NOTICE  = 5,
    LOG_INFO    = 6,
    LOG_DEBUG   = 7
};

/* --- Common VxWorks kernel function signatures ----------------------------- */

/* Task control */
STATUS  taskDelay(int ticks);
TASK_ID taskSpawn(char *name, int priority, int options, int stackSize,
                  FUNCPTR entryPt, int arg1, int arg2, int arg3,
                  int arg4, int arg5, int arg6, int arg7,
                  int arg8, int arg9, int arg10);
STATUS  taskDelete(TASK_ID tid);
STATUS  taskSuspend(TASK_ID tid);
STATUS  taskResume(TASK_ID tid);
TASK_ID taskIdSelf(void);

/* Semaphores */
SEM_ID  semBCreate(int options, int initialState);
SEM_ID  semCCreate(int options, int initialCount);
SEM_ID  semMCreate(int options);
STATUS  semTake(SEM_ID semId, int timeout);
STATUS  semGive(SEM_ID semId);
STATUS  semDelete(SEM_ID semId);

/* Memory */
void   *malloc(size_t size);
void    free(void *ptr);
void   *calloc(size_t nmemb, size_t size);
void   *realloc(void *ptr, size_t size);
void   *memPartAlloc(void *partId, size_t size);

/* I/O */
int     open(char *name, int flags, int mode);
int     close(int fd);
int     read(int fd, void *buf, size_t maxBytes);
int     write(int fd, void *buf, size_t nbytes);
STATUS  ioctl(int fd, int function, int arg);

/* Networking */
int     socket(int domain, int type, int protocol);
STATUS  bind(int s, struct sockaddr *name, int namelen);
STATUS  listen(int s, int backlog);
int     accept(int s, struct sockaddr *addr, int *addrlen);
STATUS  connect(int s, struct sockaddr *name, int namelen);
int     send(int s, char *buf, int bufLen, int flags);
int     recv(int s, char *buf, int bufLen, int flags);
STATUS  setsockopt(int s, int level, int optname, char *optval, int optlen);

/* String / printf */
int     printf(char *fmt);
int     fprintf(void *stream, char *fmt);
int     sprintf(char *s, char *fmt);
int     snprintf(char *s, size_t n, char *fmt);
int     sscanf(char *s, char *fmt);
size_t  strlen(char *s);
char   *strcpy(char *dst, char *src);
char   *strncpy(char *dst, char *src, size_t n);
char   *strcat(char *dst, char *src);
int     strcmp(char *s1, char *s2);
int     strncmp(char *s1, char *s2, size_t n);
char   *strdup(char *s);

/* System command execution (present in many VxWorks builds) */
STATUS  shellGenericInit(char *config, int stackSize, char *env,
                         char **user, int isRemote, int isConsole,
                         int inFd, int outFd, int errFd);
int     system(char *cmd);   /* may be available depending on BSP/RTP config */

#endif /* VXWORKS_H */
