/*
 * musl libc specific function signatures for radare2
 *
 * Usage: to types/musl/functions.h
 *
 * Note: musl is mostly POSIX-compatible.
 * Use types/libc/functions.h for standard libc functions.
 * This file contains musl-specific extensions and internals.
 */

/* musl internal thread functions */
void *__pthread_self(void);
int __pthread_create(void *thread, void *attr, void *start_routine, void *arg);
int __pthread_join(void *thread, void *retval);
void __pthread_exit(void *retval);
int __pthread_mutex_lock(void *mutex);
int __pthread_mutex_unlock(void *mutex);
int __pthread_mutex_trylock(void *mutex);

/* musl internal lock functions */
void __lock(void *lock);
void __unlock(void *lock);
void __lockfile(void *f);
void __unlockfile(void *f);

/* musl libc startup */
void __libc_start_main(void *main, int argc, void *argv);
void __init_libc(void *envp, char *pn);
void __libc_exit_fini(void);

/* musl internal memory functions */
void *__malloc0(int size);
void *__memalign(int align, int size);
void __malloc_atfork(int who);
void __malloc_donate(void *start, void *end);

/* musl weak aliases (common internal names) */
void *__mmap(void *addr, int length, int prot, int flags, int fd, long offset);
int __munmap(void *addr, int length);
int __mprotect(void *addr, int len, int prot);

/* musl stdio internals */
int __toread(void *f);
int __towrite(void *f);
int __overflow(void *f, int c);
int __uflow(void *f);
void *__ofl_lock(void);
void __ofl_unlock(void);
int __fmodeflags(char *mode);
void *__fdopen(int fd, char *mode);
int __stdio_close(void *f);
int __stdio_read(void *f, void *buf, int len);
int __stdio_write(void *f, void *buf, int len);
long __stdio_seek(void *f, long off, int whence);

/* musl signal internals */
int __sigaction(int sig, void *act, void *oact);
int __block_all_sigs(void *set);
int __block_app_sigs(void *set);
void __restore_sigs(void *set);

/* musl thread-local storage */
void *__tls_get_addr(void *v);
void *__copy_tls(void *mem);
int __init_tp(void *p);

/* musl dynamic linker internals */
void *__dlsym(void *handle, char *symbol, void *ra);
int __dlclose(void *handle);

/* musl errno */
int *__errno_location(void);

/* musl time functions */
int __clock_gettime(int clk, void *ts);
int __futex(void *addr, int op, int val);

/* musl string internals */
void *__memrchr(void *s, int c, int n);
void *__stpcpy(char *dest, char *src);
void *__stpncpy(char *dest, char *src, int n);

/* musl ctype locale */
void *__get_locale(int cat, char *name);
char *__lctrans(char *msg, void *lm);
char *__lctrans_cur(char *msg);
