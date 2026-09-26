/*
 * win32-security-sinks.h -- Dangerous Windows API function signatures
 *
 * Focused subset of Windows API annotated for security research.
 * Includes: command execution, code injection, unsafe string ops,
 *           format string sinks, network receive, allocators.
 *
 * Usage:
 *   to types/windows/win32-security-sinks.h
 *   tfc WinExec          # show prototype
 *   aaft                 # apply to r2 functions after aa + z/
 */

/* ============================================================================
 * CMD -- Process / Command execution
 * ============================================================================ */

/* SINK: trivial command injection -- no shell escaping */
int WinExec(char *lpCmdLine, int uCmdShow);

/* SINK: process creation -- check lpCommandLine and lpApplicationName */
int CreateProcessA(
    char *lpApplicationName,
    char *lpCommandLine,
    void *lpProcessAttributes,
    void *lpThreadAttributes,
    int bInheritHandles,
    int dwCreationFlags,
    void *lpEnvironment,
    char *lpCurrentDirectory,
    void *lpStartupInfo,
    void *lpProcessInformation
);
int CreateProcessW(
    void *lpApplicationName,
    void *lpCommandLine,
    void *lpProcessAttributes,
    void *lpThreadAttributes,
    int bInheritHandles,
    int dwCreationFlags,
    void *lpEnvironment,
    void *lpCurrentDirectory,
    void *lpStartupInfo,
    void *lpProcessInformation
);

/* SINK: shell execute -- parameter / path injection */
long ShellExecuteA(long hwnd, char *lpOperation, char *lpFile, char *lpParameters, char *lpDirectory, int nShowCmd);
long ShellExecuteW(long hwnd, void *lpOperation, void *lpFile, void *lpParameters, void *lpDirectory, int nShowCmd);

/* SINK: CRT system call -- trivial shell injection */
int system(char *command);
int _wsystem(void *command);
void *popen(char *command, char *type);
void *_popen(char *command, char *type);

/* ============================================================================
 * LOAD -- DLL / Code injection
 * ============================================================================ */

/* SINK: DLL hijacking if lpLibFileName is user-influenced */
long LoadLibraryA(char *lpLibFileName);
long LoadLibraryW(void *lpLibFileName);
long LoadLibraryExA(char *lpLibFileName, long hFile, int dwFlags);
long LoadLibraryExW(void *lpLibFileName, long hFile, int dwFlags);

/* SINK: classic code injection primitives */
int WriteProcessMemory(long hProcess, void *lpBaseAddress, void *lpBuffer, long nSize, void *lpNumberOfBytesWritten);
long CreateRemoteThread(long hProcess, void *lpThreadAttributes, long dwStackSize, void *lpStartAddress, void *lpParameter, int dwCreationFlags, void *lpThreadId);
void *VirtualAllocEx(long hProcess, void *lpAddress, long dwSize, int flAllocationType, int flProtect);

/* SINK: RWX mapping -- direct shellcode host */
void *VirtualAlloc(void *lpAddress, long dwSize, int flAllocationType, int flProtect);
int VirtualProtect(void *lpAddress, long dwSize, int flNewProtect, void *lpflOldProtect);

/* SINK: global hook -- keylogger / injection */
long SetWindowsHookExA(int idHook, void *lpfn, long hmod, int dwThreadId);
long SetWindowsHookExW(int idHook, void *lpfn, long hmod, int dwThreadId);

/* ============================================================================
 * COPY -- Unsafe string / memory copy (stack/heap overflow)
 * ============================================================================ */

/* SINK: unbounded copies -- most common CVE primitive */
char *strcpy(char *dest, char *src);
char *strcat(char *dest, char *src);
void *gets(char *str);

/* Win32 ANSI unsafe string ops */
char *lstrcpyA(char *lpString1, char *lpString2);
char *lstrcatA(char *lpString1, char *lpString2);
int lstrcmpA(char *lpString1, char *lpString2);
int lstrcmpiA(char *lpString1, char *lpString2);

/* Win32 Unicode unsafe string ops */
void *lstrcpyW(void *lpString1, void *lpString2);
void *lstrcatW(void *lpString1, void *lpString2);
int lstrcmpW(void *lpString1, void *lpString2);
int lstrcmpiW(void *lpString1, void *lpString2);

/* CRT safe-but-bounded copies (check dest size is validated) */
char *strncpy(char *dest, char *src, long count);
char *strncat(char *dest, char *src, long count);
int strncmp(char *str1, char *str2, long count);

/* Memory copies -- check size argument comes from trusted source */
void *memcpy(void *dest, void *src, long count);
void *memmove(void *dest, void *src, long count);
void *RtlCopyMemory(void *Destination, void *Source, long Length);
void *RtlMoveMemory(void *Destination, void *Source, long Length);

/* ============================================================================
 * FMT -- Format string sinks
 * ============================================================================ */

/* SINK: no bounds + format string -- CVE-class double vulnerability */
int sprintf(char *buffer, char *format, ...);
int vsprintf(char *buffer, char *format, void *argptr);
int swprintf(void *buffer, void *format, ...);

/* Win32 format string sinks */
int wsprintf(char *lpOut, char *lpFmt, ...);
int wvsprintf(char *lpOut, char *lpFmt, void *arglist);

/* Bounded but still format-string-vulnerable */
int snprintf(char *str, long size, char *format, ...);
int _snprintf(char *buffer, long count, char *format, ...);
int _vsnprintf(char *buffer, long count, char *format, void *argptr);

/* ============================================================================
 * NET -- Network receive (primary attack surface entry points)
 * ============================================================================ */

/* SINK: TCP receive -- trace forward to find parser */
int recv(long s, char *buf, int len, int flags);
int recvfrom(long s, char *buf, int len, int flags, void *from, void *fromlen);

/* Winsock overlapped receive */
int WSARecv(long s, void *lpBuffers, int dwBufferCount, void *lpNumberOfBytesRecvd, void *lpFlags, void *lpOverlapped, void *lpCompletionRoutine);
int WSARecvFrom(long s, void *lpBuffers, int dwBufferCount, void *lpNumberOfBytesRecvd, void *lpFlags, void *lpFrom, void *lpFromlen, void *lpOverlapped, void *lpCompletionRoutine);

/* WinInet / WinHTTP receive */
int InternetReadFile(long hFile, void *lpBuffer, int dwNumberOfBytesToRead, void *lpdwNumberOfBytesRead);
int WinHttpReadData(long hRequest, void *lpBuffer, int dwNumberOfBytesToRead, void *lpdwNumberOfBytesRead);

/* ============================================================================
 * HEAP -- Allocators (integer overflow in size argument)
 * ============================================================================ */

void *malloc(long size);
void *calloc(long nmemb, long size);
void *realloc(void *ptr, long size);
void *HeapAlloc(long hHeap, int dwFlags, long dwBytes);
void *HeapReAlloc(long hHeap, int dwFlags, void *lpMem, long dwBytes);
void *LocalAlloc(int uFlags, long uBytes);
void *GlobalAlloc(int uFlags, long uBytes);
void *CoTaskMemAlloc(long cb);

/* ============================================================================
 * AUTH -- Authentication functions (check return value usage)
 * ============================================================================ */

int LogonUserA(char *lpszUsername, char *lpszDomain, char *lpszPassword, int dwLogonType, int dwLogonProvider, void *phToken);
int LogonUserW(void *lpszUsername, void *lpszDomain, void *lpszPassword, int dwLogonType, int dwLogonProvider, void *phToken);

/* CryptAPI signature verification -- auth bypass if return ignored */
int CryptVerifySignature(long hHash, void *pbSignature, int dwSigLen, long hPubKey, void *sDescription, int dwFlags);
int CryptVerifySignatureA(long hHash, void *pbSignature, int dwSigLen, long hPubKey, char *sDescription, int dwFlags);
int CryptVerifySignatureW(long hHash, void *pbSignature, int dwSigLen, long hPubKey, void *sDescription, int dwFlags);

/* Comparison functions -- timing-safe versions should be used for secrets */
int memcmp(void *buf1, void *buf2, long count);
int strcmp(char *str1, char *str2);
int stricmp(char *str1, char *str2);
int lstrcmpA(char *lpString1, char *lpString2);
int lstrcmpiA(char *lpString1, char *lpString2);
