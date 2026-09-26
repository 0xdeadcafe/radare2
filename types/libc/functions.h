/*
 * Common libc function signatures for radare2
 *
 * Usage: to types/libc/functions.h
 *        tf                    # List all functions
 *        tfc malloc            # Show malloc signature
 *
 * Note: Uses basic C types for r2 compatibility
 */

/* Memory allocation */
void *malloc(int size);
void *calloc(int nmemb, int size);
void *realloc(void *ptr, int size);
void free(void *ptr);

/* String operations */
int strlen(char *s);
char *strcpy(char *dest, char *src);
char *strncpy(char *dest, char *src, int n);
char *strcat(char *dest, char *src);
char *strncat(char *dest, char *src, int n);
int strcmp(char *s1, char *s2);
int strncmp(char *s1, char *s2, int n);
char *strchr(char *s, int c);
char *strrchr(char *s, int c);
char *strstr(char *haystack, char *needle);
char *strdup(char *s);
char *strtok(char *str, char *delim);
char *strtok_r(char *str, char *delim, void *saveptr);
char *strpbrk(char *s, char *accept);
char *strsep(void *stringp, char *delim);
char *strerror(int errnum);
void perror(char *s);

/* Memory operations */
void *memcpy(void *dest, void *src, int n);
void *memmove(void *dest, void *src, int n);
void *memset(void *s, int c, int n);
int memcmp(void *s1, void *s2, int n);
void *memchr(void *s, int c, int n);
void *memmem(void *haystack, int haystacklen, void *needle, int needlelen);

/* File system operations */
int stat(char *pathname, void *statbuf);
int lstat(char *pathname, void *statbuf);
int fstat(int fd, void *statbuf);
int access(char *pathname, int mode);
int rename(char *oldpath, char *newpath);
int unlink(char *pathname);
int remove(char *pathname);
int mkdir(char *pathname, int mode);
int rmdir(char *pathname);
void *opendir(char *name);
void *readdir(void *dirp);
int closedir(void *dirp);
int chdir(char *path);
char *getcwd(char *buf, int size);
char *realpath(char *path, char *resolved_path);
int glob(char *pattern, int flags, void *errfunc, void *pglob);
void globfree(void *pglob);

/* File I/O */
int open(char *pathname, int flags);
int close(int fd);
int read(int fd, void *buf, int count);
int write(int fd, void *buf, int count);
long lseek(int fd, long offset, int whence);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int pipe(void *pipefd);
int fcntl(int fd, int cmd);
int ioctl(int fd, int request);

/* Standard I/O */
void *fopen(char *pathname, char *mode);
int fclose(void *stream);
int fread(void *ptr, int size, int nmemb, void *stream);
int fwrite(void *ptr, int size, int nmemb, void *stream);
int fseek(void *stream, long offset, int whence);
long ftell(void *stream);
void rewind(void *stream);
int feof(void *stream);
int ferror(void *stream);
int fflush(void *stream);
int fgetc(void *stream);
int fputc(int c, void *stream);
char *fgets(char *s, int size, void *stream);
int fputs(char *s, void *stream);
int getc(void *stream);
int putc(int c, void *stream);
int getchar(void);
int putchar(int c);
char *gets(char *s);
int puts(char *s);
int ungetc(int c, void *stream);

/* Formatted I/O */
int printf(char *format);
int fprintf(void *stream, char *format);
int sprintf(char *str, char *format);
int snprintf(char *str, int size, char *format);
int scanf(char *format);
int fscanf(void *stream, char *format);
int sscanf(char *str, char *format);
int vprintf(char *format, void *ap);
int vfprintf(void *stream, char *format, void *ap);
int vsprintf(char *str, char *format, void *ap);
int vsnprintf(char *str, int size, char *format, void *ap);
int dprintf(int fd, char *format);
void *popen(char *command, char *type);
int pclose(void *stream);

/* Process control */
void exit(int status);
void _exit(int status);
void abort(void);
int fork(void);
int execve(char *pathname, void *argv, void *envp);
int execv(char *pathname, void *argv);
int execvp(char *file, void *argv);
int system(char *command);
int wait(void *wstatus);
int waitpid(int pid, void *wstatus, int options);
int getpid(void);
int getppid(void);
int getuid(void);
int geteuid(void);
int getgid(void);
int getegid(void);
int setuid(int uid);
int setgid(int gid);
int kill(int pid, int sig);
void *signal(int signum, void *handler);
int daemon(int nochdir, int noclose);
int setsid(void);
int prctl(int option, long arg2, long arg3, long arg4, long arg5);

/* Memory mapping */
void *mmap(void *addr, int length, int prot, int flags, int fd, long offset);
int munmap(void *addr, int length);
int mprotect(void *addr, int len, int prot);

/* Socket operations */
int socket(int domain, int type, int protocol);
int bind(int sockfd, void *addr, int addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, void *addr, void *addrlen);
int connect(int sockfd, void *addr, int addrlen);
int send(int sockfd, void *buf, int len, int flags);
int recv(int sockfd, void *buf, int len, int flags);
int sendto(int sockfd, void *buf, int len, int flags, void *dest_addr, int addrlen);
int recvfrom(int sockfd, void *buf, int len, int flags, void *src_addr, void *addrlen);
int setsockopt(int sockfd, int level, int optname, void *optval, int optlen);
int getsockopt(int sockfd, int level, int optname, void *optval, void *optlen);
int shutdown(int sockfd, int how);
int getaddrinfo(char *node, char *service, void *hints, void *res);
void freeaddrinfo(void *res);
int getnameinfo(void *addr, int addrlen, char *host, int hostlen, char *serv, int servlen, int flags);
void *gethostbyname(char *name);
int inet_aton(char *cp, void *inp);
char *inet_ntoa(void *in);
int inet_pton(int af, char *src, void *dst);
char *inet_ntop(int af, void *src, char *dst, int size);
int socketpair(int domain, int type, int protocol, void *sv);
int select(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout);
int poll(void *fds, int nfds, int timeout);
int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, void *event);
int epoll_wait(int epfd, void *events, int maxevents, int timeout);
unsigned int htons(unsigned int hostshort);
unsigned int htonl(unsigned int hostlong);
unsigned int ntohs(unsigned int netshort);
unsigned int ntohl(unsigned int netlong);

/* Time functions */
long time(void *tloc);
int gettimeofday(void *tv, void *tz);
int nanosleep(void *req, void *rem);
int usleep(int usec);
int sleep(int seconds);

/* Environment */
char *getenv(char *name);
int setenv(char *name, char *value, int overwrite);
int unsetenv(char *name);

/* POSIX threads */
int pthread_create(void *thread, void *attr, void *start_routine, void *arg);
int pthread_join(void *thread, void *retval);
void pthread_exit(void *retval);
int pthread_cancel(void *thread);
void *pthread_self(void);
int pthread_once(void *once_control, void *init_routine);
int pthread_getspecific(int key);
int pthread_setspecific(int key, void *value);
int pthread_mutex_init(void *mutex, void *attr);
int pthread_mutex_destroy(void *mutex);
int pthread_mutex_lock(void *mutex);
int pthread_mutex_unlock(void *mutex);
int pthread_mutex_trylock(void *mutex);
int pthread_cond_init(void *cond, void *attr);
int pthread_cond_destroy(void *cond);
int pthread_cond_wait(void *cond, void *mutex);
int pthread_cond_signal(void *cond);
int pthread_cond_broadcast(void *cond);
int pthread_cond_timedwait(void *cond, void *mutex, void *abstime);
int pthread_rwlock_init(void *rwlock, void *attr);
int pthread_rwlock_destroy(void *rwlock);
int pthread_rwlock_rdlock(void *rwlock);
int pthread_rwlock_wrlock(void *rwlock);
int pthread_rwlock_unlock(void *rwlock);
int pthread_rwlock_tryrdlock(void *rwlock);
int pthread_rwlock_trywrlock(void *rwlock);

/* POSIX semaphores */
int sem_init(void *sem, int pshared, int value);
int sem_wait(void *sem);
int sem_trywait(void *sem);
int sem_post(void *sem);
int sem_destroy(void *sem);

/* Memory allocation (extended) */
void *posix_memalign(void *memptr, int alignment, int size);
void *aligned_alloc(int alignment, int size);
int malloc_usable_size(void *ptr);

/* Clocks and timers */
int clock_gettime(int clkid, void *tp);
int clock_getres(int clkid, void *res);
int clock_nanosleep(int clkid, int flags, void *request, void *remain);

/* System logging */
void openlog(char *ident, int option, int facility);
void syslog(int priority, char *format);
void closelog(void);

/* Miscellaneous */
int rand(void);
void srand(int seed);
int atoi(char *nptr);
long atol(char *nptr);
long strtol(char *nptr, void *endptr, int base);
long strtoul(char *nptr, void *endptr, int base);
void qsort(void *base, int nmemb, int size, void *compar);
void *bsearch(void *key, void *base, int nmemb, int size, void *compar);

/* File operations (extended) */
int chmod(char *pathname, int mode);
int fchmod(int fd, int mode);
int chown(char *pathname, int uid, int gid);
int fchown(int fd, int uid, int gid);
int lchown(char *pathname, int uid, int gid);
int truncate(char *path, long length);
int ftruncate(int fd, long length);
int fsync(int fd);
int fdatasync(int fd);
int readlink(char *pathname, char *buf, int bufsiz);
int symlink(char *target, char *linkpath);
int link(char *oldpath, char *newpath);
int mknod(char *pathname, int mode, int dev);
int statvfs(char *path, void *buf);
int fstatvfs(int fd, void *buf);
int inotify_init(void);
int inotify_init1(int flags);
int inotify_add_watch(int fd, char *pathname, int mask);
int inotify_rm_watch(int fd, int wd);
int sendfile(int out_fd, int in_fd, void *offset, int count);
int splice(int fd_in, void *off_in, int fd_out, void *off_out, int len, int flags);
int tee(int fd_in, int fd_out, int len, int flags);

/* Process management (extended) */
int vfork(void);
int clone(void *fn, void *stack, int flags, void *arg);
int waitid(int idtype, int id, void *infop, int options);
int setpgid(int pid, int pgid);
int getpgid(int pid);
int getsid(int pid);
int setresuid(int ruid, int euid, int suid);
int setresgid(int rgid, int egid, int sgid);
int getresuid(void *ruid, void *euid, void *suid);
int getresgid(void *rgid, void *egid, void *sgid);
int capget(void *hdrp, void *datap);
int capset(void *hdrp, void *datap);
int ptrace(int request, int pid, void *addr, void *data);

/* String (extended) */
int strcasecmp(char *s1, char *s2);
int strncasecmp(char *s1, char *s2, int n);
char *strcasestr(char *haystack, char *needle);
char *strndup(char *s, int n);
int vasprintf(void *strp, char *fmt, void *ap);
int asprintf(void *strp, char *fmt);

/* Dynamic linking */
void *dlopen(char *filename, int flags);
void *dlsym(void *handle, char *symbol);
int dlclose(void *handle);
char *dlerror(void);

/* Password / group database */
void *getpwnam(char *name);
void *getpwuid(int uid);
void *getpwent(void);
void setpwent(void);
void endpwent(void);
void *getgrnam(char *name);
void *getgrgid(int gid);

/* Limits and resources */
int getrlimit(int resource, void *rlim);
int setrlimit(int resource, void *rlim);
int getrusage(int who, void *usage);

/* Memory locking */
int mlock(void *addr, int len);
int munlock(void *addr, int len);
int mlockall(int flags);
int munlockall(void);

/* Event / timer file descriptors */
int eventfd(int initval, int flags);
int signalfd(int fd, void *mask, int flags);
int timerfd_create(int clockid, int flags);
int timerfd_settime(int fd, int flags, void *new_value, void *old_value);
int timerfd_gettime(int fd, void *curr_value);

/* POSIX regex */
int regcomp(void *preg, char *regex, int cflags);
int regexec(void *preg, char *string, int nmatch, void *pmatch, int eflags);
void regfree(void *preg);

/* Getopt */
int getopt(int argc, void *argv, char *optstring);
int getopt_long(int argc, void *argv, char *optstring, void *longopts, void *longindex);

/* Hostname */
int gethostname(char *name, int len);
int sethostname(char *name, int len);
int getdomainname(char *name, int len);

/* Cryptography */
char *crypt(char *key, char *salt);
char *crypt_r(char *key, char *salt, void *data);

/* Backtrace */
int backtrace(void *buffer, int size);
char **backtrace_symbols(void *buffer, int size);
void backtrace_symbols_fd(void *buffer, int size, int fd);

/* I/O port access (x86) */
int iopl(int level);
int ioperm(int from, int num, int turn_on);
