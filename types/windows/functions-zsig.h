/*
 * Windows CRT zsig-variant function signatures for radare2
 *
 * These are MSVC CRT function names as they appear in Windows binaries.
 * The underscore prefix is the standard MSVC convention for CRT functions.
 *
 * Usage: to types/windows/functions-zsig.h
 *        to types/windows/functions.h
 *        aaft
 */

/* ============================================================
 * Memory Allocation
 * ============================================================ */
void *_malloc(int size);
void *_calloc(int nmemb, int size);
void *_realloc(void *ptr, int size);
void _free(void *ptr);
void *_calloc_base(int nmemb, int size);
void _free_base(void *ptr);

/* Aligned allocation */
void *_aligned_malloc(int size, int alignment);
void *_aligned_realloc(void *ptr, int size, int alignment);
void *_aligned_recalloc(void *ptr, int num, int size, int alignment);
void *_aligned_offset_malloc(int size, int alignment, int offset);
void *_aligned_offset_realloc(void *ptr, int size, int alignment, int offset);
void *_aligned_offset_recalloc(void *ptr, int num, int size, int alignment, int offset);
void _aligned_free(void *ptr);
int _aligned_msize(void *ptr, int alignment, int offset);

/* Stack allocation */
void *_alloca(int size);
void *_malloca(int size);
void _freea(void *ptr);

/* Memory info */
int _msize(void *ptr);
int _heapmin(void);
int _heapwalk(void *info);
int _heapchk(void);
int _heapset(int fill);

/* ============================================================
 * Process/Thread Control
 * ============================================================ */
void _exit(int status);
void _Exit(int status);
void _cexit(void);
void _c_exit(void);
void _abort(void);
void _assert(char *msg, char *file, int line);

/* Thread functions */
long _beginthread(void *start, int stack_size, void *arglist);
long _beginthreadex(void *security, int stack_size, void *start, void *arglist, int initflag, void *thrdaddr);
void _endthread(void);
void _endthreadex(int retval);
int _getpid(void);

/* ============================================================
 * File I/O (Low-level)
 * ============================================================ */
int _open(char *filename, int oflag);
int _wopen(void *filename, int oflag);
int _sopen(char *filename, int oflag, int shflag);
int _sopen_s(void *fd, char *filename, int oflag, int shflag, int pmode);
int _close(int fd);
int _read(int fd, void *buffer, int count);
int _write(int fd, void *buffer, int count);
long _lseek(int fd, long offset, int origin);
long long _lseeki64(int fd, long long offset, int origin);
long _tell(int fd);
long long _telli64(int fd);
int _eof(int fd);
long _filelength(int fd);
long long _filelengthi64(int fd);
int _chsize(int fd, long size);
int _chsize_s(int fd, long long size);
int _commit(int fd);
int _dup(int fd);
int _dup2(int fd1, int fd2);
int _pipe(void *pfds, int psize, int textmode);
int _setmode(int fd, int mode);
int _isatty(int fd);
int _fileno(void *stream);
void *_fdopen(int fd, char *mode);

/* File management */
int _access(char *path, int mode);
int _access_s(char *path, int mode);
int _chmod(char *filename, int pmode);
int _unlink(char *filename);
int _rename(char *oldname, char *newname);
int _remove(char *path);
int _stat(char *path, void *buffer);
int _stat32(char *path, void *buffer);
int _stat64(char *path, void *buffer);
int _stati64(char *path, void *buffer);
int _fstat(int fd, void *buffer);
int _fstat32(int fd, void *buffer);
int _fstat64(int fd, void *buffer);
int _fstati64(int fd, void *buffer);
int _mkdir(char *dirname);
int _rmdir(char *dirname);
int _chdir(char *dirname);
char *_getcwd(char *buffer, int maxlen);
int _chdrive(int drive);
int _getdrive(void);

/* ============================================================
 * Standard I/O (Stream)
 * ============================================================ */
void *_fsopen(char *filename, char *mode, int shflag);
void *_wfsopen(void *filename, void *mode, int shflag);
int _fcloseall(void);
int _fgetchar(void);
int _fputchar(int c);
int _getw(void *stream);
int _putw(int w, void *stream);
int _flushall(void);
int _fseeki64(void *stream, long long offset, int origin);
long long _ftelli64(void *stream);
void *_tempnam(char *dir, char *prefix);
char *_tmpnam(char *string);
char *_tmpnam_s(char *str, int size);
void _rmtmp(void);
void _clearerr(void *stream);
void _clearerr_s(void *stream);
int _fseek_nolock(void *stream, long offset, int origin);
long _ftell_nolock(void *stream);
int _fgetc_nolock(void *stream);
int _fputc_nolock(int c, void *stream);
int _fread_nolock(void *buffer, int size, int count, void *stream);
int _fwrite_nolock(void *buffer, int size, int count, void *stream);
int _fread_nolock_s(void *buffer, int bufsize, int elemsize, int count, void *stream);

/* ============================================================
 * String Functions
 * ============================================================ */
int _strlen(char *str);
char *_strcpy(char *dest, char *src);
char *_strncpy(char *dest, char *src, int count);
char *_strcat(char *dest, char *src);
char *_strncat(char *dest, char *src, int count);
int _strcmp(char *str1, char *str2);
int _strncmp(char *str1, char *str2, int count);
int _stricmp(char *str1, char *str2);
int _strnicmp(char *str1, char *str2, int count);
int _strcmpi(char *str1, char *str2);
char *_strchr(char *str, int c);
char *_strrchr(char *str, int c);
char *_strstr(char *str, char *substr);
char *_strpbrk(char *str, char *strCharSet);
int _strspn(char *str, char *strCharSet);
int _strcspn(char *str, char *strCharSet);
char *_strtok(char *str, char *delim);
char *_strtok_s(char *str, char *delim, void *context);
char *_strdup(char *str);
char *_strlwr(char *str);
char *_strupr(char *str);
char *_strrev(char *str);
char *_strset(char *str, int c);
char *_strnset(char *str, int c, int count);
int _strerror(char *strErrMsg);
char *_strerror_s(char *buf, int size, char *msg);

/* Secure string functions */
int _strcpy_s(char *dest, int destsize, char *src);
int _strncpy_s(char *dest, int destsize, char *src, int count);
int _strcat_s(char *dest, int destsize, char *src);
int _strncat_s(char *dest, int destsize, char *src, int count);
int _strlwr_s(char *str, int size);
int _strupr_s(char *str, int size);

/* ============================================================
 * Memory Functions
 * ============================================================ */
void *_memcpy(void *dest, void *src, int count);
void *_memcpy_s(void *dest, int destsize, void *src, int count);
void *_memmove(void *dest, void *src, int count);
void *_memmove_s(void *dest, int destsize, void *src, int count);
void *_memset(void *dest, int c, int count);
int _memcmp(void *buf1, void *buf2, int count);
void *_memchr(void *buf, int c, int count);
void *_memccpy(void *dest, void *src, int c, int count);
int _memicmp(void *buf1, void *buf2, int count);

/* ============================================================
 * Character Classification
 * ============================================================ */
int _isalpha(int c);
int _isalnum(int c);
int _isdigit(int c);
int _isxdigit(int c);
int _islower(int c);
int _isupper(int c);
int _isspace(int c);
int _ispunct(int c);
int _isprint(int c);
int _isgraph(int c);
int _iscntrl(int c);
int _isascii(int c);
int _isleadbyte(int c);
int _tolower(int c);
int _toupper(int c);
int _toascii(int c);

/* Locale-aware versions */
int _isalpha_l(int c, void *locale);
int _isalnum_l(int c, void *locale);
int _isdigit_l(int c, void *locale);
int _isxdigit_l(int c, void *locale);
int _islower_l(int c, void *locale);
int _isupper_l(int c, void *locale);
int _isspace_l(int c, void *locale);
int _ispunct_l(int c, void *locale);
int _isprint_l(int c, void *locale);
int _tolower_l(int c, void *locale);
int _toupper_l(int c, void *locale);

/* ============================================================
 * Number Conversion
 * ============================================================ */
int _atoi(char *str);
long _atol(char *str);
long long _atoll(char *str);
long long _atoi64(char *str);
double _atof(char *str);
long _strtol(char *str, void *endptr, int base);
long _strtoul(char *str, void *endptr, int base);
long long _strtoll(char *str, void *endptr, int base);
long long _strtoull(char *str, void *endptr, int base);
long long _strtoi64(char *str, void *endptr, int base);
long long _strtoui64(char *str, void *endptr, int base);
double _strtod(char *str, void *endptr);
float _strtof(char *str, void *endptr);
long double _strtold(char *str, void *endptr);
char *_itoa(int value, char *str, int radix);
char *_ltoa(long value, char *str, int radix);
char *_ultoa(long value, char *str, int radix);
char *_i64toa(long long value, char *str, int radix);
char *_ui64toa(long long value, char *str, int radix);
char *_gcvt(double value, int digits, char *buffer);
char *_ecvt(double value, int count, void *dec, void *sign);
char *_fcvt(double value, int count, void *dec, void *sign);

/* Secure versions */
int _itoa_s(int value, char *buffer, int size, int radix);
int _ltoa_s(long value, char *buffer, int size, int radix);
int _ultoa_s(long value, char *buffer, int size, int radix);
int _i64toa_s(long long value, char *buffer, int size, int radix);
int _ui64toa_s(long long value, char *buffer, int size, int radix);

/* ============================================================
 * Math Functions
 * ============================================================ */
double _sin(double x);
double _cos(double x);
double _tan(double x);
double _asin(double x);
double _acos(double x);
double _atan(double x);
double _atan2(double y, double x);
double _sinh(double x);
double _cosh(double x);
double _tanh(double x);
double _exp(double x);
double _log(double x);
double _log10(double x);
double _pow(double x, double y);
double _sqrt(double x);
double _ceil(double x);
double _floor(double x);
double _fabs(double x);
double _fmod(double x, double y);
double _modf(double x, void *intpart);
double _frexp(double x, void *expptr);
double _ldexp(double x, int exp);
double _hypot(double x, double y);

/* Float versions */
float _sinf(float x);
float _cosf(float x);
float _tanf(float x);
float _asinf(float x);
float _acosf(float x);
float _atanf(float x);
float _atan2f(float y, float x);
float _sinhf(float x);
float _coshf(float x);
float _tanhf(float x);
float _expf(float x);
float _logf(float x);
float _log10f(float x);
float _powf(float x, float y);
float _sqrtf(float x);
float _ceilf(float x);
float _floorf(float x);
float _fabsf(float x);
float _fmodf(float x, float y);

/* C99/C11 math */
double _asinh(double x);
double _acosh(double x);
double _atanh(double x);
double _cbrt(double x);
double _expm1(double x);
double _log1p(double x);
double _log2(double x);
double _logb(double x);
double _scalbn(double x, int n);
double _scalbln(double x, long n);
int _ilogb(double x);
double _copysign(double x, double y);
double _fdim(double x, double y);
double _fmax(double x, double y);
double _fmin(double x, double y);
double _fma(double x, double y, double z);
double _nan(char *tagp);
double _nextafter(double x, double y);
double _remainder(double x, double y);
double _remquo(double x, double y, void *quo);
double _round(double x);
double _trunc(double x);
double _nearbyint(double x);
double _rint(double x);
long _lrint(double x);
long long _llrint(double x);
long _lround(double x);
long long _llround(double x);
double _erf(double x);
double _erfc(double x);
double _lgamma(double x);
double _tgamma(double x);

/* Float versions of C99 */
float _asinhf(float x);
float _acoshf(float x);
float _atanhf(float x);
float _cbrtf(float x);
float _expm1f(float x);
float _log1pf(float x);
float _log2f(float x);
float _copysignf(float x, float y);
float _fdimf(float x, float y);
float _fmaxf(float x, float y);
float _fminf(float x, float y);
float _fmaf(float x, float y, float z);
float _nanf(char *tagp);
float _roundf(float x);
float _truncf(float x);
float _nearbyintf(float x);
float _rintf(float x);
long _lrintf(float x);
long long _llrintf(float x);

/* Floating point control */
int _isnan(double x);
int _isnanf(float x);
int _finite(double x);
int _finitef(float x);
int _fpclass(double x);
int _fpclassf(float x);
double _chgsign(double x);
float _chgsignf(float x);
int _controlfp(int new_val, int mask);
int _controlfp_s(void *current, int new_val, int mask);
int _control87(int new_val, int mask);
int _clearfp(void);
int _statusfp(void);
void _fpreset(void);

/* ============================================================
 * Time Functions
 * ============================================================ */
long _time(void *timer);
long _time32(void *timer);
long long _time64(void *timer);
double _difftime(long time1, long time0);
double _difftime32(long time1, long time0);
double _difftime64(long long time1, long long time0);
void *_localtime(void *timer);
void *_localtime32(void *timer);
void *_localtime64(void *timer);
int _localtime_s(void *tm, void *timer);
int _localtime32_s(void *tm, void *timer);
int _localtime64_s(void *tm, void *timer);
void *_gmtime(void *timer);
void *_gmtime32(void *timer);
void *_gmtime64(void *timer);
int _gmtime_s(void *tm, void *timer);
int _gmtime32_s(void *tm, void *timer);
int _gmtime64_s(void *tm, void *timer);
long _mktime(void *tm);
long _mktime32(void *tm);
long long _mktime64(void *tm);
char *_ctime(void *timer);
char *_ctime32(void *timer);
char *_ctime64(void *timer);
int _ctime_s(char *buf, int size, void *timer);
int _ctime32_s(char *buf, int size, void *timer);
int _ctime64_s(char *buf, int size, void *timer);
char *_asctime(void *tm);
int _asctime_s(char *buf, int size, void *tm);
int _strftime(char *str, int maxsize, char *format, void *tm);
int _strftime_l(char *str, int maxsize, char *format, void *tm, void *locale);
long _clock(void);
void _tzset(void);
int _ftime(void *tp);
int _ftime32(void *tp);
int _ftime64(void *tp);
int _ftime_s(void *tp);
int _ftime32_s(void *tp);
int _ftime64_s(void *tp);
int _utime(char *filename, void *times);
int _utime32(char *filename, void *times);
int _utime64(char *filename, void *times);
int _futime(int fd, void *times);
int _futime32(int fd, void *times);
int _futime64(int fd, void *times);

/* ============================================================
 * Error Handling
 * ============================================================ */
int *_errno(void);
void _set_errno(int err);
int _get_errno(void *pValue);
char *_sys_errlist;
int _sys_nerr;
void _perror(char *string);
int _set_error_mode(int mode);

/* Invalid parameter handling */
void _invalid_parameter(void *expression, void *function, void *file, int line, int reserved);
void _invalid_parameter_noinfo(void);
void _invalid_parameter_noinfo_noreturn(void);
void _invoke_watson(void *expression, void *function, void *file, int line, int reserved);

/* ============================================================
 * Locale
 * ============================================================ */
char *_setlocale(int category, char *locale);
void *_create_locale(int category, char *locale);
void _free_locale(void *locale);
void *_get_current_locale(void);
void _configthreadlocale(int per_thread_locale_type);

/* ============================================================
 * Signal Handling
 * ============================================================ */
void *_signal(int sig, void *handler);
int _raise(int sig);

/* ============================================================
 * Environment
 * ============================================================ */
char *_getenv(char *varname);
int _getenv_s(void *size, char *buf, int count, char *varname);
int _putenv(char *envstring);
int _putenv_s(char *name, char *value);
int _searchenv(char *filename, char *varname, char *pathname);
int _searchenv_s(char *filename, char *varname, char *pathname, int size);
char **_environ;
void *_wenviron;

/* ============================================================
 * Security (Buffer overrun detection)
 * ============================================================ */
void __security_check_cookie(int cookie);
void __security_init_cookie(void);
int __report_gsfailure(void);

/* ============================================================
 * Debug CRT Functions
 * ============================================================ */
void *_malloc_dbg(int size, int blockType, char *filename, int linenumber);
void *_calloc_dbg(int num, int size, int blockType, char *filename, int linenumber);
void *_realloc_dbg(void *userData, int newSize, int blockType, char *filename, int linenumber);
void _free_dbg(void *userData, int blockType);
int _CrtDbgReport(int reportType, char *filename, int linenumber, char *moduleName, char *format);
int _CrtSetReportMode(int reportType, int reportMode);
void *_CrtSetReportFile(int reportType, void *reportFile);
int _CrtSetReportHook(void *pfnNewHook);
int _CrtSetDbgFlag(int newFlag);
int _CrtCheckMemory(void);
void _CrtDumpMemoryLeaks(void);
void _CrtMemCheckpoint(void *state);
void _CrtMemDifference(void *stateDiff, void *oldState, void *newState);
void _CrtMemDumpStatistics(void *state);
void _CrtMemDumpAllObjectsSince(void *state);
int _CrtIsValidHeapPointer(void *userData);
int _CrtIsMemoryBlock(void *userData, int size, void *requestNumber, void *filename, void *linenumber);
