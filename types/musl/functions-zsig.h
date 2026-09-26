/*
 * musl libc zsig-variant function signatures for radare2
 *
 * These are function names as they appear after zsig matching.
 * radare2's aaft command matches function names exactly, so we need
 * both canonical names and the __ prefixed internal names.
 *
 * Usage: to types/musl/functions-zsig.h
 *        to types/musl/functions.h
 *        aaft
 */

/* ============================================================
 * Memory Allocation (libc internals)
 * ============================================================ */
void *__libc_malloc(int size);
void *__libc_calloc(int nmemb, int size);
void __libc_free(void *ptr);
void *__malloc_alloc_meta(void *group, int idx, int size);
int __malloc_allzerop(void *p);
void *__simple_malloc(int size);

/* ============================================================
 * Thread/Lock Primitives
 * ============================================================ */
void __acquire_ptc(void);
void __release_ptc(void);
void __inhibit_ptc(void);
void __tl_lock(void);
void __tl_unlock(void);
void __tl_sync(int);

/* ============================================================
 * Signal Handling
 * ============================================================ */
int __libc_sigaction(int sig, void *act, void *oact);
void __get_handler_set(void *set);
void __restore(void);

/* ============================================================
 * Process/Fork
 * ============================================================ */
void __fork_handler(int who);
void __post_Fork(int ret);
void __aio_atfork(int who);

/* ============================================================
 * AIO (Async I/O)
 * ============================================================ */
void __aio_close(int fd);
void *__aio_get_queue(int fd, int need);
void __aio_unref_queue(void *q);

/* ============================================================
 * Clone/Thread Creation
 * ============================================================ */
int __clone(void *fn, void *stack, int flags, void *arg);
int __set_thread_area(void *p);
void __unmapself(void *base, int size);

/* ============================================================
 * Time Functions
 * ============================================================ */
int __clock_nanosleep(int clk, int flags, void *req, void *rem);
char *__asctime_r(void *tm, char *buf);
void *__gmtime_r(void *t, void *tm);
void *__localtime_r(void *t, void *tm);
long __secs_to_tm(long long t, void *tm);
long long __tm_to_secs(void *tm);
void __secs_to_zone(long long t, int local, void *tm, char **zone, long *gmtoff);
char *__tm_to_tzname(void *tm);
void __tzset(void);
long __month_to_secs(int month, int is_leap);
long long __year_to_secs(long long year, void *is_leap);

/* ============================================================
 * Math Functions (Internal)
 * ============================================================ */
double __cos(double x, double y);
float __cosdf(double x);
long double __cosl(long double x, long double y);
double __sin(double x, double y);
float __sindf(double x);
long double __sinl(long double x, long double y);
double __tan(double x, double y);
float __tandf(double x, int odd);
long double __tanl(long double x, long double y, int odd);
double __expo2(double x, double sign);
float __expo2f(float x, float sign);
int __rem_pio2(double x, void *y);
int __rem_pio2f(float x, void *y);
int __rem_pio2l(long double x, void *y);
void __rem_pio2_large(void *x, void *y, int e0, int nx, int prec);
double __lgamma_r(double x, void *signgamp);
float __lgammaf_r(float x, void *signgamp);
long double __lgammal_r(long double x, void *signgamp);
double __invtrigl_R(long double z);
double __p1evll(long double x, void *coef, int n);
double __polevll(long double x, void *coef, int n);

/* Math error handling */
double __math_divzero(int sign);
float __math_divzerof(int sign);
double __math_invalid(double x);
float __math_invalidf(float x);
long double __math_invalidl(long double x);
double __math_oflow(int sign);
float __math_oflowf(int sign);
double __math_uflow(int sign);
float __math_uflowf(int sign);
double __math_xflow(int sign, double y);
float __math_xflowf(int sign, float y);

/* Classification */
int __fpclassify(double x);
int __fpclassifyf(float x);
int __fpclassifyl(long double x);
int __signbit(double x);
int __signbitf(float x);
int __signbitl(long double x);

/* Complex math */
double __ldexp_cexp(void *z, int exp);
float __ldexp_cexpf(void *z, int exp);

/* ============================================================
 * Crypt Functions
 * ============================================================ */
char *__crypt_r(char *key, char *salt, void *data);
char *__crypt_blowfish(char *key, char *salt, void *data);
char *__crypt_des(char *key, char *salt, void *data);
char *__crypt_md5(char *key, char *salt, void *data);
char *__crypt_sha256(char *key, char *salt, void *data);
char *__crypt_sha512(char *key, char *salt, void *data);
void __des_setkey(void *key, void *ekey);
void __do_des(int m, void *in, void *out, void *key);

/* ============================================================
 * Ctype/Locale Functions
 * ============================================================ */
void *__ctype_b_loc(void);
int __ctype_get_mb_cur_max(void);
void *__ctype_tolower_loc(void);
void *__ctype_toupper_loc(void);
int __tolower_l(int c, void *loc);
int __toupper_l(int c, void *loc);
void *__duplocale(void *loc);
void *__newlocale(int mask, char *name, void *base);
void *__uselocale(void *loc);
void *__get_locale(int cat, char *name);
char *__nl_langinfo(int item);
char *__nl_langinfo_l(int item, void *loc);
int __loc_is_allocated(void *loc);

/* Character classification (locale) */
int __isalnum_l(int c, void *loc);
int __isalpha_l(int c, void *loc);
int __isblank_l(int c, void *loc);
int __iscntrl_l(int c, void *loc);
int __isdigit_l(int c, void *loc);
int __isgraph_l(int c, void *loc);
int __islower_l(int c, void *loc);
int __isprint_l(int c, void *loc);
int __ispunct_l(int c, void *loc);
int __isspace_l(int c, void *loc);
int __isupper_l(int c, void *loc);
int __isxdigit_l(int c, void *loc);

/* Wide character classification (locale) */
int __iswalnum_l(int wc, void *loc);
int __iswalpha_l(int wc, void *loc);
int __iswblank_l(int wc, void *loc);
int __iswcntrl_l(int wc, void *loc);
int __iswctype_l(int wc, int type, void *loc);
int __iswdigit_l(int wc, void *loc);
int __iswgraph_l(int wc, void *loc);
int __iswlower_l(int wc, void *loc);
int __iswprint_l(int wc, void *loc);
int __iswpunct_l(int wc, void *loc);
int __iswspace_l(int wc, void *loc);
int __iswupper_l(int wc, void *loc);
int __iswxdigit_l(int wc, void *loc);
int __towctrans_l(int wc, void *trans, void *loc);
int __towlower_l(int wc, void *loc);
int __towupper_l(int wc, void *loc);
void *__wctrans_l(char *name, void *loc);
void *__wctype_l(char *name, void *loc);

/* ============================================================
 * String Functions (Locale)
 * ============================================================ */
int __strcasecmp_l(char *s1, char *s2, void *loc);
int __strncasecmp_l(char *s1, char *s2, int n, void *loc);
int __strcoll_l(char *s1, char *s2, void *loc);
int __strxfrm_l(char *dest, char *src, int n, void *loc);
char *__strerror_l(int errnum, void *loc);
int __strftime_l(char *s, int max, char *fmt, void *tm, void *loc);
void *__strftime_fmt_1(void *s, void *tm, int item, void *loc);

/* Wide string (locale) */
int __wcscoll_l(void *s1, void *s2, void *loc);
int __wcsxfrm_l(void *dest, void *src, int n, void *loc);
int __wcsftime_l(void *s, int max, void *fmt, void *tm, void *loc);

/* String internals */
char *__strchrnul(char *s, int c);

/* ============================================================
 * C++ ABI
 * ============================================================ */
int __cxa_atexit(void *func, void *arg, void *dso);
void __cxa_finalize(void *dso);

/* ============================================================
 * Dynamic Linker Internals
 * ============================================================ */
void __dl_seterr(char *fmt);
void __dl_vseterr(char *fmt, void *ap);
void __dl_thread_cleanup(void);

/* ============================================================
 * DNS/Network
 * ============================================================ */
int __dn_expand(void *base, void *end, void *src, char *dest, int space);
int __dns_parse(void *r, int rlen, void *callback, void *ctx);
int __lookup_name(void *buf, char *canon, char *name, int family, int flags);
int __lookup_ipliteral(void *buf, char *name, int family);
int __lookup_serv(void *buf, char *name, int proto, int socktype, int flags);
int __res_mkquery(int op, char *dname, int cls, int type, void *data, int datalen, void *newrr, void *buf, int buflen);
int __res_send(void *msg, int msglen, void *ans, int anslen);
int __res_msend(int nqueries, void *queries, void *qlens, void *answers, void *alens, int asize);
int __res_msend_rc(int nqueries, void *queries, void *qlens, void *answers, void *alens, int asize, void *conf);
void *__res_state(void);
int __get_resolv_conf(void *conf, char *search, int search_sz);
int __netlink_enumerate(int link, int af, void *cb, void *ctx);
int __rtnetlink_enumerate(int link, int af, void *cb, void *ctx);

/* ============================================================
 * Stat/Filesystem
 * ============================================================ */
int __fstat(int fd, void *st);
int __fstatat(int fd, char *path, void *st, int flag);
int __fstatfs(int fd, void *st);
int __statfs(char *path, void *st);
int __fxstat(int ver, int fd, void *st);
int __fxstatat(int ver, int fd, char *path, void *st, int flag);
int __lxstat(int ver, char *path, void *st);
int __xstat(int ver, char *path, void *st);
int __xmknod(int ver, char *path, int mode, void *dev);
int __xmknodat(int ver, int fd, char *path, int mode, void *dev);

/* ============================================================
 * File Descriptor Operations
 * ============================================================ */
int __dup3(int old, int new_fd, int flags);
long __lseek(int fd, long offset, int whence);
int __fseeko(void *f, long off, int whence);
int __fseeko_unlocked(void *f, long off, int whence);
long __ftello(void *f);
long __ftello_unlocked(void *f);
int __futimesat(int fd, char *path, void *times);

/* ============================================================
 * Stdio Internals
 * ============================================================ */
int __fclose_ca(void *f);
void *__fopen_rb_ca(char *path, void *f, void *buf, int size);
int __fgetwc_unlocked(void *f);
int __fputwc_unlocked(int c, void *f);
int __fwritex(void *s, int len, void *f);
int __toread_needs_stdio_exit(void *f);
int __towrite_needs_stdio_exit(void *f);
void __stdio_exit(void);
int __stdout_write(void *f, void *buf, int len);
int __fseterr(void *f);
void __register_locked_file(void *f, void *self);
void __unlist_locked_file(void *f);
void __do_orphaned_stdio_locks(void);

/* BSD stdio extensions */
int __fbufsize(void *f);
int __flbf(void *f);
int __fpending(void *f);
void __fpurge(void *f);
int __freadable(void *f);
int __freadahead(void *f);
int __freading(void *f);
void *__freadptr(void *f, void *size);
void __freadptrinc(void *f, int inc);
int __fsetlocking(void *f, int type);
int __fwritable(void *f);
int __fwriting(void *f);

/* ============================================================
 * Number Parsing
 * ============================================================ */
int __floatscan(void *f, int prec, int pok);
long long __intscan(void *f, int base, int pok, long long lim);
void __shlim(void *f, long lim);
int __shgetc(void *f);

/* ============================================================
 * Environment
 * ============================================================ */
int __putenv(char *s, int a);
void __env_rm_add(char *old, char *new_str);

/* ============================================================
 * Exec
 * ============================================================ */
int __execvpe(char *file, void *argv, void *envp);

/* ============================================================
 * getopt
 * ============================================================ */
int __getopt_long(int argc, void *argv, char *optstring, void *longopts, void *idx, int longonly);
void __getopt_msg(char *prog, char *errstr, char *optchar, int optlen);

/* ============================================================
 * User/Group Database
 * ============================================================ */
int __getpw_a(char *name, int uid, void *pw, void *buf, int size, void *res);
int __getpwent_a(void *f, void *pw, void *buf, int size, void *res);
int __getgr_a(char *name, int gid, void *gr, void *buf, int size, void *res);
int __getgrent_a(void *f, void *gr, void *buf, int size, void *res);
int __parsespent(char *s, void *sp);
int __ptsname_r(int fd, char *buf, int size);

/* ============================================================
 * Hash Search (hsearch)
 * ============================================================ */
int __hcreate_r(int nel, void *tab);
void __hdestroy_r(void *tab);
int __hsearch_r(void *item, int action, void *ret, void *tab);
void *__tsearch_balance(void *p);

/* ============================================================
 * Cancellation
 * ============================================================ */
void __cancel(void);
void __testcancel(void);
void __do_cleanup_push(void *cb);
void __do_cleanup_pop(void *cb);

/* ============================================================
 * Pthread Internals
 * ============================================================ */
int __pthread_cond_timedwait(void *c, void *m, void *ts);
int __pthread_detach(void *t);
int __pthread_equal(void *a, void *b);
void *__pthread_getspecific(int key);
int __pthread_key_create(void *key, void *dtor);
int __pthread_key_delete(int key);
void __pthread_key_atfork(int who);
int __pthread_mutex_timedlock(void *m, void *ts);
int __pthread_mutex_trylock_owner(void *m, void *tid);
int __pthread_once(void *control, void *init);
void __pthread_once_full(void *control, void *init);
int __pthread_rwlock_rdlock(void *rw);
int __pthread_rwlock_wrlock(void *rw);
int __pthread_rwlock_tryrdlock(void *rw);
int __pthread_rwlock_trywrlock(void *rw);
int __pthread_rwlock_timedrdlock(void *rw, void *ts);
int __pthread_rwlock_timedwrlock(void *rw, void *ts);
int __pthread_rwlock_unlock(void *rw);
void *__pthread_self_internal(void);
int __pthread_setcancelstate(int state, void *old);
void __pthread_testcancel(void);
int __pthread_timedjoin_np(void *t, void *res, void *ts);
int __pthread_tryjoin_np(void *t, void *res);
void __pthread_tsd_run_dtors(void);
void __private_cond_signal(void *c, int n);

/* ============================================================
 * Futex/Wait
 * ============================================================ */
int __timedwait(void *addr, int val, int clk, void *ts);
int __timedwait_cp(void *addr, int val, int clk, void *ts);
int __wait(void *addr, void *waiters, int val, int priv);
void __wake(void *addr, int cnt, int priv);

/* ============================================================
 * Memory/VM
 * ============================================================ */
int __madvise(void *addr, int length, int advice);
void *__mremap(void *addr, int old_len, int new_len, int flags);
void *__map_file(char *path, void *size);
void __vm_lock(void);
void __vm_unlock(void);
void __vm_wait(void);
int __membarrier_init(void);
int __membarrier(int cmd, int flags);

/* ============================================================
 * TLS (Thread-Local Storage)
 * ============================================================ */
void __reset_tls(void);
void *__tlsdesc_static(void *p);
void *__tlsdesc_dynamic(void *p);

/* ============================================================
 * Random
 * ============================================================ */
int __srandom(int seed);
char *__randname(char *buf);
int __rand48_step(void *xi, void *lc);

/* ============================================================
 * Misc Internals
 * ============================================================ */
void __assert_fail(char *expr, char *file, int line, char *func);
void __stack_chk_fail(void);
long __getauxval(long type);
void *__vdsosym(char *name, char *ver);
int __flt_rounds(void);
int __fesetround(int round);
void __synccall(void *func, void *ctx);
int __syscall_cp(int n);
int __syscall_cp_c(int n);
int __syscall_ret(long r);
void __setxid(void);
int __setjmp(void *jb);
void __sigsetjmp_tail(void *jb, int ret);
void __procfdname(char *buf, int pid);
int __mkostemps(char *template, int suffixlen, int flags);
void *__mo_lookup(void *p, int size, char *s);
char *__gettextdomain(void);
int __pleval(char *s, int n);
char *__lctrans_impl(char *msg, void *lm);

/* Exit handlers */
void __funcs_on_exit(void);
void __funcs_on_quick_exit(void);

/* Sorting */
void __qsort_r(void *base, int nmemb, int size, void *cmp, void *arg);

/* Error location */
int *__h_errno_location(void);

/* NSCD */
void *__nscd_query(int type, char *name, void *buf, int len, void *swap);

/* utmp */
void __utmpxname(char *name);

/* syslog */
void __vsyslog(int priority, char *fmt, void *ap);

/* sched */
int __sched_cpucount(int size, void *set);

/* Regex internals */
void *__tre_mem_new_impl(int provided, void *prov);
void *__tre_mem_alloc_impl(void *mem, int prov, void *prov_p, int zero, int size);
void __tre_mem_destroy(void *mem);

/* OFL (open file list) */
void *__ofl_add(void *f);

/* Signal RT min/max */
int __libc_current_sigrtmin(void);
int __libc_current_sigrtmax(void);

/* LSB compatibility */
long __lsysinfo(void);

/* SSP */
void __init_ssp(void *auxv);
