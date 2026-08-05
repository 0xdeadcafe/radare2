/*
 * Android bionic libc function signatures for radare2
 *
 * Usage: to types/android/functions.h
 *        tf __system_property_get
 *
 * Note: Most bionic functions are POSIX-compatible.
 * Use types/libc/functions.h for standard libc functions.
 * This file contains Android-specific extensions.
 */

/* System properties */
int __system_property_get(char *name, char *value);
int __system_property_set(char *name, char *value);
void *__system_property_find(char *name);
int __system_property_read(void *pi, char *name, char *value);
void *__system_property_find_nth(int n);
int __system_property_foreach(void *callback, void *cookie);

/* Bionic-specific memory functions */
void *memalign(int alignment, int size);
int posix_memalign(void *memptr, int alignment, int size);
void *pvalloc(int size);
void *valloc(int size);

/* Thread-local storage */
int pthread_key_create(void *key, void *destructor);
int pthread_key_delete(int key);
void *pthread_getspecific(int key);
int pthread_setspecific(int key, void *value);

/* Bionic atomics (legacy) */
int __atomic_cmpxchg(int old, int new_val, void *ptr);
int __atomic_swap(int new_val, void *ptr);
int __atomic_dec(void *ptr);
int __atomic_inc(void *ptr);

/* Dynamic linker */
void *dlopen(char *filename, int flags);
void *dlsym(void *handle, char *symbol);
int dlclose(void *handle);
char *dlerror(void);
int dladdr(void *addr, void *info);

/* dlopen flags */
enum dlopen_flags {
    RTLD_NOW    = 0x00002,
    RTLD_LAZY   = 0x00001,
    RTLD_LOCAL  = 0x00000,
    RTLD_GLOBAL = 0x00100,
    RTLD_NOLOAD = 0x00004,
    RTLD_NODELETE = 0x01000
};

/* Android-specific file operations */
int __openat(int dirfd, char *pathname, int flags, int mode);
int __fstatat64(int dirfd, char *pathname, void *buf, int flags);

/* Bionic-specific string functions */
int strlcpy(char *dst, char *src, int size);
int strlcat(char *dst, char *src, int size);

/* Android linker namespace (API 24+) */
void *android_dlopen_ext(char *filename, int flag, void *extinfo);
void *android_get_exported_namespace(char *name);
int android_link_namespaces(void *from, void *to, char *shared_libs_sonames);
void *android_create_namespace(char *name, char *ld_library_path, char *default_library_path, long type, char *permitted_when_isolated_path, void *parent);

/* Bionic-specific process functions */
int prctl(int option, long arg2, long arg3, long arg4, long arg5);
int tgkill(int tgid, int tid, int sig);
int tkill(int tid, int sig);
long syscall(long number);

/* setjmp/longjmp */
int setjmp(void *env);
int _setjmp(void *env);
int sigsetjmp(void *env, int savesigs);
void longjmp(void *env, int val);
void _longjmp(void *env, int val);
void siglongjmp(void *env, int val);

/* Locale (limited in bionic) */
void *setlocale(int category, char *locale);
void *uselocale(void *newloc);

/* Error handling */
int *__errno(void);
void __set_errno(int n);
