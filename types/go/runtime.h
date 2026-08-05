/*
 * Go runtime internal type definitions for radare2
 *
 * Covers Go 1.18+ (generics era) runtime internals.
 * Useful for analyzing stripped Go binaries, Go malware, and Go-based tools.
 *
 * Usage:
 *   to go/runtime.h
 *   tsc go_g          -- goroutine descriptor
 *   tsc go_iface      -- interface value
 *   te go_gstatus     -- goroutine status codes
 *
 * Note: Go binaries >= 1.2 carry a pclntab (PC/line table) that r2 uses to
 * recover function names automatically via `aaa`. This file provides the
 * underlying struct layouts for manual analysis when pclntab is stripped
 * or when annotating variables in the heap/stack.
 *
 * All sizes are for amd64 (64-bit). ARM64 layout is identical for these
 * structs except pointer size is always 8 bytes on both.
 *
 * Sources: src/runtime/runtime2.go, src/runtime/type.go (Go 1.21-1.23)
 */

/* ============================================================================
 * Goroutine status (g.atomicstatus field values)
 * ============================================================================ */

enum go_gstatus {
    _Gidle         = 0,  /* just allocated, not yet initialized */
    _Grunnable     = 1,  /* on run queue, not executing */
    _Grunning      = 2,  /* executing on an M (OS thread) */
    _Gsyscall      = 3,  /* in a system call */
    _Gwaiting      = 4,  /* blocked (chan recv, select, sleep, etc.) */
    _Gdead         = 6,  /* goroutine has exited or being reused */
    _Gcopystack    = 8,  /* stack being moved */
    _Gpreempted    = 9,  /* stopped due to preemption */
    _Gscan         = 4096 /* GC scanning this goroutine's stack */
};

/* ============================================================================
 * Wait reason codes (g.waitreason -- why goroutine is blocked)
 * ============================================================================ */

enum go_waitreason {
    waitReasonZero          = 0,
    waitReasonGCAssistWait  = 1,
    waitReasonChannelReceive= 6,
    waitReasonChannelSend   = 7,
    waitReasonFinalizerWait = 8,
    waitReasonForceGCIdle   = 9,
    waitReasonSemacquire    = 10,
    waitReasonSleep         = 11,
    waitReasonSyncCondWait  = 12,
    waitReasonTimerGoroutine= 13,
    waitReasonTraceReaderBlocked = 14,
    waitReasonWaitForGCCycle= 15,
    waitReasonGCWorkerIdle  = 16,
    waitReasonSelectNoCases = 17,
    waitReasonSelect        = 18
};

/* ============================================================================
 * Stack descriptor (runtime.stack)
 * Represents the current stack bounds of a goroutine.
 * ============================================================================ */

struct go_stack {
    void *lo;   /* lowest valid address */
    void *hi;   /* one-past-the-end of stack memory */
};

/* ============================================================================
 * Goroutine descriptor (runtime.g)
 * Every goroutine has one. The current goroutine's g pointer is in register:
 *   amd64: TLS segment (fs:-8)  -- r2: `drr fs` then offset -8
 *   arm64: R28
 *   x86:   TLS segment (gs:-4)
 *
 * Key fields for manual analysis (offsets for amd64 Go 1.21+):
 *   [  0] stack.lo    -- lowest stack address
 *   [  8] stack.hi    -- highest stack address
 *   [ 16] stackguard0 -- stack overflow check sentinel
 *   [ 24] stackguard1 -- non-Go stack sentinel
 *   [120] m           -- OS thread (M) currently running this goroutine
 *   [128] sched       -- saved scheduler context (sp, pc, g, ctxt)
 *   [168] atomicstatus-- goroutine status (enum go_gstatus)
 *   [192] goid        -- unique goroutine ID (int64)
 *   [232] gopc        -- PC where go statement was executed
 * ============================================================================ */

struct go_g {
    struct go_stack stack;       /* [  0] current stack bounds */
    void *stackguard0;           /* [ 16] overflow check (sp < guard = grow) */
    void *stackguard1;           /* [ 24] non-Go stack overflow check */
    void *_panic;                /* [ 32] innermost panic (runtime._panic*) */
    void *_defer;                /* [ 40] innermost deferred function */
    void *m;                     /* [ 48] current M (nil if not running) */
    void *sched_sp;              /* [ 56] saved stack pointer */
    void *sched_pc;              /* [ 64] saved program counter */
    void *sched_g;               /* [ 72] self pointer (for restoration) */
    void *sched_ctxt;            /* [ 80] additional context */
    void *syscallsp;             /* [ 88] SP during syscall */
    void *syscallpc;             /* [ 96] PC during syscall */
    void *stktopsp;              /* [104] expected stack top SP during traceback */
    void *param;                 /* [112] wakeup parameter */
    int   atomicstatus;          /* [120] goroutine status (go_gstatus) */
    int   stackLock;             /* [124] stack lock */
    long long goid;              /* [128] goroutine unique ID */
    long long schedlink;         /* [136] run queue linkage */
    long waittill_nsec;          /* [144] nanoseconds of wait (for sleep) */
    int waitreason;              /* [152] why goroutine is waiting */
    int preempt;                 /* [156] preempt requested */
    int preemptStop;             /* [157] transition to _Gpreempted on preempt */
    int asyncSafePoint;          /* [158] stopped at async safepoint */
    int paniconfault;            /* [159] panic on fault (for sys.Memmove etc.) */
    int gcscandone;              /* [160] g has scanned stack */
    int throwsplit;              /* [161] must not split stack */
    int activeStackChans;        /* [162] chan ops on stack, unsafe to grow */
    int parkingOnChan;           /* [163] about to park on a channel */
    int raceignore;              /* [164] ignore race detection events */
    int tracking;                /* [165] whether we're tracking goroutine */
    int trackingSeq;             /* [166] sequence # for tracking */
    long long trackingStamp;     /* [168] timestamp of when tracking started */
    long long raceaddr;          /* [176] race address being accessed */
    long long gopc;              /* [184] PC of the go statement that created this goroutine */
    void *ancestors;             /* [192] ancestor info for -traceback=all */
    long long startpc;           /* [200] PC of goroutine function */
    void *racectx;               /* [208] race context */
    void *waiting;               /* [216] runtime.sudog linked list */
    void *cgoCtxt;               /* [224] cgo traceback context */
    void *labels;                /* [232] profiler labels */
    void *timer;                 /* [240] cached timer for time.Sleep */
    int selectDone;              /* [248] CAS to 1 to win select race */
};

/* ============================================================================
 * M descriptor (runtime.m) -- OS thread wrapper
 * Key fields only; full struct is 500+ bytes.
 * ============================================================================ */

struct go_m {
    void *g0;           /* [  0] goroutine with scheduler stack */
    void *morebuf_sp;   /* [  8] saved SP for morestack */
    void *morebuf_pc;   /* [ 16] saved PC for morestack */
    void *morebuf_lr;   /* [ 24] saved LR for morestack */
    void *morebuf_g;    /* [ 32] pointer to g that called morestack */
    void *gsignal;      /* [ 40] signal-handling goroutine */
    void *goSigStack;   /* [ 48] Go-allocated signal handling stack */
    void *sigmask;      /* [ 56] storage for saved signal mask */
    long long procid;   /* [ 64] for debuggers -- thread ID */
    void *gsignalstack; /* [ 72] signal handling stack (if alt stack) */
    int gsignalstacksz; /* [ 80] size of signal handling stack */
    int throwing;       /* [ 84] runtime throw depth */
    void *preemptoff;   /* [ 88] keep goroutines on this M (non-empty = preempt off) */
    int locks;          /* [ 96] number of logical locks held */
    int dying;          /* [100] if 1, immediately crash */
    int profilehz;      /* [104] CPU profiling rate */
    void *curg;         /* [112] current running goroutine */
    void *caughtsig;    /* [120] goroutine running signal handler */
    void *p;            /* [128] attached P for executing Go code (nil if not) */
    void *nextp;        /* [136] next P */
    void *oldp;         /* [144] P before entering syscall */
    long long id;       /* [152] M unique ID */
    int mallocing;      /* [160] malloc in progress */
    int throwing2;      /* [161] throw in progress */
    void *nextwaitm;    /* [168] next M waiting for lock */
    long long waitunlockf; /* [176] unlock function */
    void *waitlock;     /* [184] mutex/chan waiting for */
    void *note;         /* [192] sleep/wakeup note */
    long long notesema; /* [200] semaphore for note */
    long long fastrand; /* [208] per-M RNG state */
    long long ncgocall; /* [216] cgo call count */
    int ncgo;           /* [224] cgo calls in progress on stack */
    int cgoCallersUse;  /* [228] use in cgo traceback */
};

/* ============================================================================
 * Interface value (runtime.iface / runtime.eface)
 * Every Go interface value is two pointers: type info + data.
 * An empty interface (interface{} / any) uses eface.
 * Non-empty interfaces use iface with an itab pointer.
 * ============================================================================ */

/* Non-empty interface: iface{itab, data} */
struct go_iface {
    void *tab;   /* pointer to itab (type+interface method table) */
    void *data;  /* pointer to value (heap-allocated if value doesn't fit in pointer) */
};

/* Empty interface (interface{} / any): eface{_type, data} */
struct go_eface {
    void *_type; /* pointer to runtime._type */
    void *data;  /* pointer to value */
};

/* ============================================================================
 * Type descriptor (runtime._type)
 * Every Go type has one of these at compile time.
 * ============================================================================ */

struct go_type {
    long long size;         /* [  0] size in bytes */
    long long ptrdata;      /* [  8] number of bytes that can contain pointers */
    int hash;               /* [ 16] type hash for switch/interface comparison */
    char tflag;             /* [ 20] extra type information flags */
    char align;             /* [ 21] alignment of variable with this type */
    char fieldAlign;        /* [ 22] alignment of struct field with this type */
    char kind;              /* [ 23] type kind (see go_kind enum) */
    void *equal;            /* [ 24] comparison function for objects of this type */
    void *gcdata;           /* [ 32] GC type data */
    int str;                /* [ 40] string form (nameOff) */
    int ptrToThis;          /* [ 44] type for pointer to this type (typeOff) */
};

/* ============================================================================
 * Type kind codes (the 'kind' byte in go_type)
 * ============================================================================ */

enum go_kind {
    go_Invalid         = 0,
    go_Bool            = 1,
    go_Int             = 2,
    go_Int8            = 3,
    go_Int16           = 4,
    go_Int32           = 5,
    go_Int64           = 6,
    go_Uint            = 7,
    go_Uint8           = 8,
    go_Uint16          = 9,
    go_Uint32          = 10,
    go_Uint64          = 11,
    go_Uintptr         = 12,
    go_Float32         = 13,
    go_Float64         = 14,
    go_Complex64       = 15,
    go_Complex128      = 16,
    go_Array           = 17,
    go_Chan            = 18,
    go_Func            = 19,
    go_Interface       = 20,
    go_Map             = 21,
    go_Pointer         = 22,
    go_Slice           = 23,
    go_String          = 24,
    go_Struct          = 25,
    go_UnsafePointer   = 26
};

/* ============================================================================
 * String header (runtime.stringStruct)
 * Go strings are (ptr, len) pairs -- NOT null-terminated.
 * ============================================================================ */

struct go_string {
    void *str;   /* pointer to UTF-8 bytes */
    long  len;   /* byte length (NOT character count for non-ASCII) */
};

/* ============================================================================
 * Slice header (runtime.slice)
 * Go slices are (ptr, len, cap) triples.
 * ============================================================================ */

struct go_slice {
    void *array; /* pointer to underlying array */
    long  len;   /* number of elements present */
    long  cap;   /* capacity of underlying array */
};

/* ============================================================================
 * Channel (runtime.hchan) -- partial layout
 * ============================================================================ */

struct go_hchan {
    long qcount;    /* [  0] total data in the queue */
    long dataqsiz;  /* [  8] size of circular queue */
    void *buf;      /* [ 16] points to array of dataqsiz elements */
    int elemsize;   /* [ 24] size of one element */
    int closed;     /* [ 28] channel has been closed */
    void *elemtype; /* [ 32] element type (go_type*) */
    long sendx;     /* [ 40] send index */
    long recvx;     /* [ 48] receive index */
    void *recvq;    /* [ 56] list of recv waiters (sudog*) */
    void *sendq;    /* [ 64] list of send waiters (sudog*) */
    long  lock;     /* [ 72] mutex (runtime.mutex) */
};

/* ============================================================================
 * Map header (runtime.hmap) -- partial layout
 * ============================================================================ */

struct go_hmap {
    long  count;    /* [  0] number of live cells */
    char  flags;    /* [  8] state flags */
    char  B;        /* [  9] log_2 of # buckets (can hold up to 6.5 * 2^B) */
    short noverflow;/* [ 10] approximate number of overflow buckets */
    int   hash0;    /* [ 12] hash seed */
    void *buckets;  /* [ 16] array of 2^B buckets (nil if count==0) */
    void *oldbuckets;/* [ 24] previous bucket array (half the size) during grow */
    long  nevacuate;/* [ 32] progress counter for evacuation */
    void *extra;    /* [ 40] optional fields (overflow/oldoverflow/nextoverflow) */
};

/* ============================================================================
 * Defer record (runtime._defer)
 * Forms a linked list at g._defer.
 * ============================================================================ */

struct go_defer {
    int started;     /* [  0] 1 = defer function has started executing */
    int heap;        /* [  4] allocated on heap, not stack */
    int openDefer;   /* [  8] record for an open-coded defer */
    void *sp;        /* [ 16] stack pointer at time of defer */
    void *pc;        /* [ 24] program counter at time of defer */
    void *fn;        /* [ 32] function to be deferred */
    void *_panic;    /* [ 40] panic that is running defer */
    void *link;      /* [ 48] next defer on stack (_defer*) */
    void *fd;        /* [ 56] funcdata for open-coded defer */
    void *varp;      /* [ 64] value of varp at time of defer */
    void *framepc;   /* [ 72] current pc associated with the frame */
};
