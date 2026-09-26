/*
 * Android logging (logcat) type definitions for radare2
 *
 * Usage: to types/android/log.h
 *        te android_LogPriority
 *        tf __android_log_print
 *
 * These are the functions used for Android native logging.
 */

/* Log priority levels */
enum android_LogPriority {
    ANDROID_LOG_UNKNOWN = 0,
    ANDROID_LOG_DEFAULT = 1,
    ANDROID_LOG_VERBOSE = 2,
    ANDROID_LOG_DEBUG   = 3,
    ANDROID_LOG_INFO    = 4,
    ANDROID_LOG_WARN    = 5,
    ANDROID_LOG_ERROR   = 6,
    ANDROID_LOG_FATAL   = 7,
    ANDROID_LOG_SILENT  = 8
};

/* Logging functions */
int __android_log_write(int prio, char *tag, char *text);
int __android_log_print(int prio, char *tag, char *fmt);
int __android_log_vprint(int prio, char *tag, char *fmt, void *ap);
void __android_log_assert(char *cond, char *tag, char *fmt);
int __android_log_buf_write(int bufID, int prio, char *tag, char *text);
int __android_log_buf_print(int bufID, int prio, char *tag, char *fmt);

/* Log buffer IDs */
enum log_id {
    LOG_ID_MIN     = 0,
    LOG_ID_MAIN    = 0,
    LOG_ID_RADIO   = 1,
    LOG_ID_EVENTS  = 2,
    LOG_ID_SYSTEM  = 3,
    LOG_ID_CRASH   = 4,
    LOG_ID_STATS   = 5,
    LOG_ID_SECURITY = 6,
    LOG_ID_KERNEL  = 7,
    LOG_ID_MAX     = 8
};
