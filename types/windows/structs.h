/*
 * Windows common structures for radare2
 *
 * Usage: to types/windows/structs.h
 *
 * Note: Sizes assume x64 Windows (LP64 with LLP64 quirks)
 * HANDLE/pointers are 8 bytes on x64, 4 bytes on x86
 */

/* ============================================================================
 * Basic Windows Structures
 * ============================================================================ */

/* GUID - 16 bytes */
struct GUID {
    int Data1;
    short Data2;
    short Data3;
    char Data4[8];
};

/* UNICODE_STRING - 16 bytes on x64 */
struct UNICODE_STRING {
    short Length;
    short MaximumLength;
    int Padding;
    long Buffer;
};

/* LIST_ENTRY - 16 bytes on x64 */
struct LIST_ENTRY {
    long Flink;
    long Blink;
};

/* LARGE_INTEGER - 8 bytes */
struct LARGE_INTEGER {
    int LowPart;
    int HighPart;
};

/* FILETIME - 8 bytes */
struct FILETIME {
    int dwLowDateTime;
    int dwHighDateTime;
};

/* SYSTEMTIME - 16 bytes */
struct SYSTEMTIME {
    short wYear;
    short wMonth;
    short wDayOfWeek;
    short wDay;
    short wHour;
    short wMinute;
    short wSecond;
    short wMilliseconds;
};

/* ============================================================================
 * Security Structures
 * ============================================================================ */

/* SECURITY_ATTRIBUTES - 24 bytes on x64 */
struct SECURITY_ATTRIBUTES {
    int nLength;
    int Padding;
    long lpSecurityDescriptor;
    int bInheritHandle;
    int Padding2;
};

/* LUID - 8 bytes */
struct LUID {
    int LowPart;
    int HighPart;
};

/* LUID_AND_ATTRIBUTES - 12 bytes */
struct LUID_AND_ATTRIBUTES {
    int LowPart;
    int HighPart;
    int Attributes;
};

/* SID_IDENTIFIER_AUTHORITY - 6 bytes */
struct SID_IDENTIFIER_AUTHORITY {
    char Value[6];
};

/* ============================================================================
 * I/O Structures
 * ============================================================================ */

/* OVERLAPPED - 32 bytes on x64 */
struct OVERLAPPED {
    long Internal;
    long InternalHigh;
    int Offset;
    int OffsetHigh;
    long hEvent;
};

/* IO_STATUS_BLOCK - 16 bytes on x64 */
struct IO_STATUS_BLOCK {
    long Status;
    long Information;
};

/* ============================================================================
 * Process/Thread Structures
 * ============================================================================ */

/* STARTUPINFOA - 104 bytes on x64 */
struct STARTUPINFOA {
    int cb;
    int Padding;
    long lpReserved;
    long lpDesktop;
    long lpTitle;
    int dwX;
    int dwY;
    int dwXSize;
    int dwYSize;
    int dwXCountChars;
    int dwYCountChars;
    int dwFillAttribute;
    int dwFlags;
    short wShowWindow;
    short cbReserved2;
    long lpReserved2;
    long hStdInput;
    long hStdOutput;
    long hStdError;
};

/* PROCESS_INFORMATION - 24 bytes on x64 */
struct PROCESS_INFORMATION {
    long hProcess;
    long hThread;
    int dwProcessId;
    int dwThreadId;
};

/* PROCESS_BASIC_INFORMATION - 48 bytes on x64 */
struct PROCESS_BASIC_INFORMATION {
    long ExitStatus;
    long PebBaseAddress;
    long AffinityMask;
    long BasePriority;
    long UniqueProcessId;
    long InheritedFromUniqueProcessId;
};

/* CLIENT_ID - 16 bytes on x64 */
struct CLIENT_ID {
    long UniqueProcess;
    long UniqueThread;
};

/* ============================================================================
 * Memory Structures
 * ============================================================================ */

/* MEMORY_BASIC_INFORMATION - 48 bytes on x64 */
struct MEMORY_BASIC_INFORMATION {
    long BaseAddress;
    long AllocationBase;
    int AllocationProtect;
    short PartitionId;
    short Padding;
    long RegionSize;
    int State;
    int Protect;
    int Type;
    int Padding2;
};

/* ============================================================================
 * File Structures
 * ============================================================================ */

/* WIN32_FIND_DATAA - 320 bytes */
struct WIN32_FIND_DATAA {
    int dwFileAttributes;
    int ftCreationTime_low;
    int ftCreationTime_high;
    int ftLastAccessTime_low;
    int ftLastAccessTime_high;
    int ftLastWriteTime_low;
    int ftLastWriteTime_high;
    int nFileSizeHigh;
    int nFileSizeLow;
    int dwReserved0;
    int dwReserved1;
    char cFileName[260];
    char cAlternateFileName[14];
    short Padding;
};

/* BY_HANDLE_FILE_INFORMATION - 52 bytes */
struct BY_HANDLE_FILE_INFORMATION {
    int dwFileAttributes;
    int ftCreationTime_low;
    int ftCreationTime_high;
    int ftLastAccessTime_low;
    int ftLastAccessTime_high;
    int ftLastWriteTime_low;
    int ftLastWriteTime_high;
    int dwVolumeSerialNumber;
    int nFileSizeHigh;
    int nFileSizeLow;
    int nNumberOfLinks;
    int nFileIndexHigh;
    int nFileIndexLow;
};

/* ============================================================================
 * Registry Structures
 * ============================================================================ */

/* KEY_VALUE_PARTIAL_INFORMATION - variable */
struct KEY_VALUE_PARTIAL_INFORMATION {
    int TitleIndex;
    int Type;
    int DataLength;
    char Data[4];
};

/* ============================================================================
 * Exception Structures
 * ============================================================================ */

/* EXCEPTION_RECORD - 152 bytes on x64 */
struct EXCEPTION_RECORD {
    int ExceptionCode;
    int ExceptionFlags;
    long ExceptionRecord;
    long ExceptionAddress;
    int NumberParameters;
    int Padding;
    long ExceptionInformation[15];
};

/* CONTEXT partial - key registers for x64 */
struct CONTEXT_PARTIAL {
    long P1Home;
    long P2Home;
    long P3Home;
    long P4Home;
    long P5Home;
    long P6Home;
    int ContextFlags;
    int MxCsr;
    short SegCs;
    short SegDs;
    short SegEs;
    short SegFs;
    short SegGs;
    short SegSs;
    int EFlags;
    long Dr0;
    long Dr1;
    long Dr2;
    long Dr3;
    long Dr6;
    long Dr7;
    long Rax;
    long Rcx;
    long Rdx;
    long Rbx;
    long Rsp;
    long Rbp;
    long Rsi;
    long Rdi;
    long R8;
    long R9;
    long R10;
    long R11;
    long R12;
    long R13;
    long R14;
    long R15;
    long Rip;
};
