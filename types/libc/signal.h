/*
 * Linux signal numbers for radare2
 *
 * Usage: to types/libc/signal.h
 *        te linux_signal
 *        te linux_signal 9    # Returns SIGKILL
 *
 * Standard signals (1-31) are same across Linux architectures
 */

enum linux_signal {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    SIGIOT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGSTKFLT = 16,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    SIGWINCH = 28,
    SIGIO = 29,
    SIGPOLL = 29,
    SIGPWR = 30,
    SIGSYS = 31,
    SIGUNUSED = 31
};

/* Signal action flags */
enum linux_sa_flags {
    SA_NOCLDSTOP = 1,
    SA_NOCLDWAIT = 2,
    SA_SIGINFO = 4,
    SA_ONSTACK = 0x08000000,
    SA_RESTART = 0x10000000,
    SA_NODEFER = 0x40000000,
    SA_RESETHAND = 0x80000000
};

/* Signal action structure */
struct sigaction {
    void *sa_handler;
    void *sa_sigaction;
    int   sa_flags;
    void *sa_restorer;
    int   sa_mask[2];
};

/* Signal functions */
void *signal(int signum, void *handler);
/* sigaction() - use sigaction struct pointer; decl omitted to avoid shadowing struct sigaction */
int sigprocmask(int how, void *set, void *oldset);
int sigpending(void *set);
int sigsuspend(void *mask);
int sigwait(void *set, void *sig);
int sigemptyset(void *set);
int sigfillset(void *set);
int sigaddset(void *set, int signum);
int sigdelset(void *set, int signum);
int sigismember(void *set, int signum);
int raise(int sig);
int kill(int pid, int sig);
int killpg(int pgrp, int sig);
int sigqueue(int pid, int sig, void *value);
unsigned int alarm(unsigned int seconds);
int pause(void);
