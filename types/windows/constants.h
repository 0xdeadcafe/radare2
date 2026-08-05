/*
 * Windows API constants for radare2
 *
 * Usage: to types/windows/constants.h
 */

/* ============================================================================
 * File Access Rights
 * ============================================================================ */

enum win_generic_access {
    GENERIC_READ = 0x80000000,
    GENERIC_WRITE = 0x40000000,
    GENERIC_EXECUTE = 0x20000000,
    GENERIC_ALL = 0x10000000
};

enum win_file_access {
    FILE_READ_DATA = 0x0001,
    FILE_LIST_DIRECTORY = 0x0001,
    FILE_WRITE_DATA = 0x0002,
    FILE_ADD_FILE = 0x0002,
    FILE_APPEND_DATA = 0x0004,
    FILE_ADD_SUBDIRECTORY = 0x0004,
    FILE_CREATE_PIPE_INSTANCE = 0x0004,
    FILE_READ_EA = 0x0008,
    FILE_WRITE_EA = 0x0010,
    FILE_EXECUTE = 0x0020,
    FILE_TRAVERSE = 0x0020,
    FILE_DELETE_CHILD = 0x0040,
    FILE_READ_ATTRIBUTES = 0x0080,
    FILE_WRITE_ATTRIBUTES = 0x0100
};

/* ============================================================================
 * File Share Mode
 * ============================================================================ */

enum win_file_share {
    FILE_SHARE_READ = 0x00000001,
    FILE_SHARE_WRITE = 0x00000002,
    FILE_SHARE_DELETE = 0x00000004
};

/* ============================================================================
 * File Creation Disposition
 * ============================================================================ */

enum win_creation_disposition {
    CREATE_NEW = 1,
    CREATE_ALWAYS = 2,
    OPEN_EXISTING = 3,
    OPEN_ALWAYS = 4,
    TRUNCATE_EXISTING = 5
};

/* ============================================================================
 * File Attributes
 * ============================================================================ */

enum win_file_attributes {
    FILE_ATTRIBUTE_READONLY = 0x00000001,
    FILE_ATTRIBUTE_HIDDEN = 0x00000002,
    FILE_ATTRIBUTE_SYSTEM = 0x00000004,
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010,
    FILE_ATTRIBUTE_ARCHIVE = 0x00000020,
    FILE_ATTRIBUTE_DEVICE = 0x00000040,
    FILE_ATTRIBUTE_NORMAL = 0x00000080,
    FILE_ATTRIBUTE_TEMPORARY = 0x00000100,
    FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200,
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400,
    FILE_ATTRIBUTE_COMPRESSED = 0x00000800,
    FILE_ATTRIBUTE_OFFLINE = 0x00001000,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000,
    FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
};

/* ============================================================================
 * Memory Protection
 * ============================================================================ */

enum win_page_protect {
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_WRITECOPY = 0x08,
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,
    PAGE_GUARD = 0x100,
    PAGE_NOCACHE = 0x200,
    PAGE_WRITECOMBINE = 0x400
};

enum win_mem_type {
    MEM_COMMIT = 0x00001000,
    MEM_RESERVE = 0x00002000,
    MEM_DECOMMIT = 0x00004000,
    MEM_RELEASE = 0x00008000,
    MEM_FREE = 0x00010000,
    MEM_PRIVATE = 0x00020000,
    MEM_MAPPED = 0x00040000,
    MEM_RESET = 0x00080000,
    MEM_TOP_DOWN = 0x00100000,
    MEM_WRITE_WATCH = 0x00200000,
    MEM_PHYSICAL = 0x00400000,
    MEM_LARGE_PAGES = 0x20000000
};

/* ============================================================================
 * Process Access Rights
 * ============================================================================ */

enum win_process_access {
    PROCESS_TERMINATE = 0x0001,
    PROCESS_CREATE_THREAD = 0x0002,
    PROCESS_SET_SESSIONID = 0x0004,
    PROCESS_VM_OPERATION = 0x0008,
    PROCESS_VM_READ = 0x0010,
    PROCESS_VM_WRITE = 0x0020,
    PROCESS_DUP_HANDLE = 0x0040,
    PROCESS_CREATE_PROCESS = 0x0080,
    PROCESS_SET_QUOTA = 0x0100,
    PROCESS_SET_INFORMATION = 0x0200,
    PROCESS_QUERY_INFORMATION = 0x0400,
    PROCESS_SUSPEND_RESUME = 0x0800,
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
    PROCESS_ALL_ACCESS = 0x1FFFFF
};

/* ============================================================================
 * Thread Access Rights
 * ============================================================================ */

enum win_thread_access {
    THREAD_TERMINATE = 0x0001,
    THREAD_SUSPEND_RESUME = 0x0002,
    THREAD_GET_CONTEXT = 0x0008,
    THREAD_SET_CONTEXT = 0x0010,
    THREAD_SET_INFORMATION = 0x0020,
    THREAD_QUERY_INFORMATION = 0x0040,
    THREAD_SET_THREAD_TOKEN = 0x0080,
    THREAD_IMPERSONATE = 0x0100,
    THREAD_DIRECT_IMPERSONATION = 0x0200,
    THREAD_SET_LIMITED_INFORMATION = 0x0400,
    THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
    THREAD_ALL_ACCESS = 0x1FFFFF
};

/* ============================================================================
 * Registry
 * ============================================================================ */

enum win_reg_type {
    REG_NONE = 0,
    REG_SZ = 1,
    REG_EXPAND_SZ = 2,
    REG_BINARY = 3,
    REG_DWORD = 4,
    REG_DWORD_LITTLE_ENDIAN = 4,
    REG_DWORD_BIG_ENDIAN = 5,
    REG_LINK = 6,
    REG_MULTI_SZ = 7,
    REG_RESOURCE_LIST = 8,
    REG_FULL_RESOURCE_DESCRIPTOR = 9,
    REG_RESOURCE_REQUIREMENTS_LIST = 10,
    REG_QWORD = 11,
    REG_QWORD_LITTLE_ENDIAN = 11
};

enum win_reg_key {
    HKEY_CLASSES_ROOT = 0x80000000,
    HKEY_CURRENT_USER = 0x80000001,
    HKEY_LOCAL_MACHINE = 0x80000002,
    HKEY_USERS = 0x80000003,
    HKEY_PERFORMANCE_DATA = 0x80000004,
    HKEY_CURRENT_CONFIG = 0x80000005
};

/* ============================================================================
 * Wait Constants
 * ============================================================================ */

enum win_wait {
    WAIT_OBJECT_0 = 0x00000000,
    WAIT_ABANDONED = 0x00000080,
    WAIT_TIMEOUT = 0x00000102,
    WAIT_FAILED = 0xFFFFFFFF,
    INFINITE = 0xFFFFFFFF
};

/* ============================================================================
 * Standard Handles
 * ============================================================================ */

enum win_std_handle {
    STD_INPUT_HANDLE = 0xFFFFFFF6,
    STD_OUTPUT_HANDLE = 0xFFFFFFF5,
    STD_ERROR_HANDLE = 0xFFFFFFF4
};

/* ============================================================================
 * Token Access Rights
 * ============================================================================ */

enum win_token_access {
    TOKEN_ASSIGN_PRIMARY = 0x0001,
    TOKEN_DUPLICATE = 0x0002,
    TOKEN_IMPERSONATE = 0x0004,
    TOKEN_QUERY = 0x0008,
    TOKEN_QUERY_SOURCE = 0x0010,
    TOKEN_ADJUST_PRIVILEGES = 0x0020,
    TOKEN_ADJUST_GROUPS = 0x0040,
    TOKEN_ADJUST_DEFAULT = 0x0080,
    TOKEN_ADJUST_SESSIONID = 0x0100,
    TOKEN_ALL_ACCESS = 0xF01FF
};

/* ============================================================================
 * Exception Codes
 * ============================================================================ */

enum win_exception {
    EXCEPTION_ACCESS_VIOLATION = 0xC0000005,
    EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002,
    EXCEPTION_BREAKPOINT = 0x80000003,
    EXCEPTION_SINGLE_STEP = 0x80000004,
    EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C,
    EXCEPTION_FLT_DENORMAL_OPERAND = 0xC000008D,
    EXCEPTION_FLT_DIVIDE_BY_ZERO = 0xC000008E,
    EXCEPTION_FLT_INEXACT_RESULT = 0xC000008F,
    EXCEPTION_FLT_INVALID_OPERATION = 0xC0000090,
    EXCEPTION_FLT_OVERFLOW = 0xC0000091,
    EXCEPTION_FLT_STACK_CHECK = 0xC0000092,
    EXCEPTION_FLT_UNDERFLOW = 0xC0000093,
    EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094,
    EXCEPTION_INT_OVERFLOW = 0xC0000095,
    EXCEPTION_PRIV_INSTRUCTION = 0xC0000096,
    EXCEPTION_IN_PAGE_ERROR = 0xC0000006,
    EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D,
    EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xC0000025,
    EXCEPTION_STACK_OVERFLOW = 0xC00000FD,
    EXCEPTION_INVALID_DISPOSITION = 0xC0000026,
    EXCEPTION_GUARD_PAGE = 0x80000001,
    EXCEPTION_INVALID_HANDLE = 0xC0000008
};
