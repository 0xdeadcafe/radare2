/*
 * Windows API function signatures for radare2
 *
 * Usage: to types/windows/functions.h
 *        tf                    # List all functions
 *        tfc CreateFileA       # Show function signature
 */

/* ============================================================================
 * File Operations
 * ============================================================================ */

long CreateFileA(char *lpFileName, int dwDesiredAccess, int dwShareMode, void *lpSecurityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, long hTemplateFile);
long CreateFileW(void *lpFileName, int dwDesiredAccess, int dwShareMode, void *lpSecurityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, long hTemplateFile);
int ReadFile(long hFile, void *lpBuffer, int nNumberOfBytesToRead, void *lpNumberOfBytesRead, void *lpOverlapped);
int WriteFile(long hFile, void *lpBuffer, int nNumberOfBytesToWrite, void *lpNumberOfBytesWritten, void *lpOverlapped);
int CloseHandle(long hObject);
int DeleteFileA(char *lpFileName);
int DeleteFileW(void *lpFileName);
int CopyFileA(char *lpExistingFileName, char *lpNewFileName, int bFailIfExists);
int MoveFileA(char *lpExistingFileName, char *lpNewFileName);
long SetFilePointer(long hFile, int lDistanceToMove, void *lpDistanceToMoveHigh, int dwMoveMethod);
int SetEndOfFile(long hFile);
int FlushFileBuffers(long hFile);
int GetFileSize(long hFile, void *lpFileSizeHigh);
int GetFileAttributesA(char *lpFileName);
int SetFileAttributesA(char *lpFileName, int dwFileAttributes);
long FindFirstFileA(char *lpFileName, void *lpFindFileData);
int FindNextFileA(long hFindFile, void *lpFindFileData);
int FindClose(long hFindFile);

/* ============================================================================
 * Memory Operations
 * ============================================================================ */

void *VirtualAlloc(void *lpAddress, long dwSize, int flAllocationType, int flProtect);
int VirtualFree(void *lpAddress, long dwSize, int dwFreeType);
int VirtualProtect(void *lpAddress, long dwSize, int flNewProtect, void *lpflOldProtect);
long VirtualQuery(void *lpAddress, void *lpBuffer, long dwLength);
void *VirtualAllocEx(long hProcess, void *lpAddress, long dwSize, int flAllocationType, int flProtect);
int VirtualFreeEx(long hProcess, void *lpAddress, long dwSize, int dwFreeType);
int VirtualProtectEx(long hProcess, void *lpAddress, long dwSize, int flNewProtect, void *lpflOldProtect);
int ReadProcessMemory(long hProcess, void *lpBaseAddress, void *lpBuffer, long nSize, void *lpNumberOfBytesRead);
int WriteProcessMemory(long hProcess, void *lpBaseAddress, void *lpBuffer, long nSize, void *lpNumberOfBytesWritten);

long HeapCreate(int flOptions, long dwInitialSize, long dwMaximumSize);
int HeapDestroy(long hHeap);
void *HeapAlloc(long hHeap, int dwFlags, long dwBytes);
void *HeapReAlloc(long hHeap, int dwFlags, void *lpMem, long dwBytes);
int HeapFree(long hHeap, int dwFlags, void *lpMem);
long HeapSize(long hHeap, int dwFlags, void *lpMem);
long GetProcessHeap(void);

void *LocalAlloc(int uFlags, long uBytes);
void *LocalReAlloc(void *hMem, long uBytes, int uFlags);
void *LocalFree(void *hMem);
void *GlobalAlloc(int uFlags, long uBytes);
void *GlobalReAlloc(void *hMem, long uBytes, int uFlags);
void *GlobalFree(void *hMem);

/* ============================================================================
 * Process/Thread Operations
 * ============================================================================ */

int CreateProcessA(char *lpApplicationName, char *lpCommandLine, void *lpProcessAttributes, void *lpThreadAttributes, int bInheritHandles, int dwCreationFlags, void *lpEnvironment, char *lpCurrentDirectory, void *lpStartupInfo, void *lpProcessInformation);
long OpenProcess(int dwDesiredAccess, int bInheritHandle, int dwProcessId);
int TerminateProcess(long hProcess, int uExitCode);
int GetExitCodeProcess(long hProcess, void *lpExitCode);
int GetCurrentProcessId(void);
long GetCurrentProcess(void);

long CreateThread(void *lpThreadAttributes, long dwStackSize, void *lpStartAddress, void *lpParameter, int dwCreationFlags, void *lpThreadId);
long OpenThread(int dwDesiredAccess, int bInheritHandle, int dwThreadId);
int TerminateThread(long hThread, int dwExitCode);
int SuspendThread(long hThread);
int ResumeThread(long hThread);
int GetThreadContext(long hThread, void *lpContext);
int SetThreadContext(long hThread, void *lpContext);
int GetCurrentThreadId(void);
long GetCurrentThread(void);
void ExitThread(int dwExitCode);
void ExitProcess(int uExitCode);

/* ============================================================================
 * Synchronization
 * ============================================================================ */

int WaitForSingleObject(long hHandle, int dwMilliseconds);
int WaitForMultipleObjects(int nCount, void *lpHandles, int bWaitAll, int dwMilliseconds);
long CreateMutexA(void *lpMutexAttributes, int bInitialOwner, char *lpName);
int ReleaseMutex(long hMutex);
long CreateEventA(void *lpEventAttributes, int bManualReset, int bInitialState, char *lpName);
int SetEvent(long hEvent);
int ResetEvent(long hEvent);
long CreateSemaphoreA(void *lpSemaphoreAttributes, int lInitialCount, int lMaximumCount, char *lpName);
int ReleaseSemaphore(long hSemaphore, int lReleaseCount, void *lpPreviousCount);
void InitializeCriticalSection(void *lpCriticalSection);
void DeleteCriticalSection(void *lpCriticalSection);
void EnterCriticalSection(void *lpCriticalSection);
void LeaveCriticalSection(void *lpCriticalSection);
int TryEnterCriticalSection(void *lpCriticalSection);
void Sleep(int dwMilliseconds);

/* ============================================================================
 * Module Operations
 * ============================================================================ */

long LoadLibraryA(char *lpLibFileName);
long LoadLibraryW(void *lpLibFileName);
long LoadLibraryExA(char *lpLibFileName, long hFile, int dwFlags);
int FreeLibrary(long hLibModule);
void *GetProcAddress(long hModule, char *lpProcName);
long GetModuleHandleA(char *lpModuleName);
long GetModuleHandleW(void *lpModuleName);
int GetModuleFileNameA(long hModule, char *lpFilename, int nSize);

/* ============================================================================
 * Registry Operations
 * ============================================================================ */

int RegOpenKeyExA(long hKey, char *lpSubKey, int ulOptions, int samDesired, void *phkResult);
int RegCloseKey(long hKey);
int RegQueryValueExA(long hKey, char *lpValueName, void *lpReserved, void *lpType, void *lpData, void *lpcbData);
int RegSetValueExA(long hKey, char *lpValueName, int Reserved, int dwType, void *lpData, int cbData);
int RegCreateKeyExA(long hKey, char *lpSubKey, int Reserved, char *lpClass, int dwOptions, int samDesired, void *lpSecurityAttributes, void *phkResult, void *lpdwDisposition);
int RegDeleteKeyA(long hKey, char *lpSubKey);
int RegDeleteValueA(long hKey, char *lpValueName);
int RegEnumKeyExA(long hKey, int dwIndex, char *lpName, void *lpcchName, void *lpReserved, char *lpClass, void *lpcchClass, void *lpftLastWriteTime);
int RegEnumValueA(long hKey, int dwIndex, char *lpValueName, void *lpcchValueName, void *lpReserved, void *lpType, void *lpData, void *lpcbData);

/* ============================================================================
 * Security Operations
 * ============================================================================ */

int OpenProcessToken(long ProcessHandle, int DesiredAccess, void *TokenHandle);
int OpenThreadToken(long ThreadHandle, int DesiredAccess, int OpenAsSelf, void *TokenHandle);
int GetTokenInformation(long TokenHandle, int TokenInformationClass, void *TokenInformation, int TokenInformationLength, void *ReturnLength);
int SetTokenInformation(long TokenHandle, int TokenInformationClass, void *TokenInformation, int TokenInformationLength);
int AdjustTokenPrivileges(long TokenHandle, int DisableAllPrivileges, void *NewState, int BufferLength, void *PreviousState, void *ReturnLength);
int LookupPrivilegeValueA(char *lpSystemName, char *lpName, void *lpLuid);
int ImpersonateLoggedOnUser(long hToken);
int RevertToSelf(void);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

int GetLastError(void);
void SetLastError(int dwErrCode);
int FormatMessageA(int dwFlags, void *lpSource, int dwMessageId, int dwLanguageId, char *lpBuffer, int nSize, void *Arguments);

/* ============================================================================
 * Miscellaneous
 * ============================================================================ */

void OutputDebugStringA(char *lpOutputString);
int IsDebuggerPresent(void);
void DebugBreak(void);
int GetTickCount(void);
long GetTickCount64(void);
void GetSystemTime(void *lpSystemTime);
void GetLocalTime(void *lpSystemTime);
int QueryPerformanceCounter(void *lpPerformanceCount);
int QueryPerformanceFrequency(void *lpFrequency);
int GetComputerNameA(char *lpBuffer, void *nSize);
int GetUserNameA(char *lpBuffer, void *pcbBuffer);
char *GetCommandLineA(void);
char *GetEnvironmentStrings(void);
int GetEnvironmentVariableA(char *lpName, char *lpBuffer, int nSize);
int SetEnvironmentVariableA(char *lpName, char *lpValue);

/* ============================================================================
 * Cryptography (CryptoAPI / BCrypt)
 * ============================================================================ */

/* Legacy CryptoAPI (wincrypt.h) */
int CryptAcquireContextA(void *phProv, char *szContainer, char *szProvider, int dwProvType, int dwFlags);
int CryptAcquireContextW(void *phProv, void *szContainer, void *szProvider, int dwProvType, int dwFlags);
int CryptReleaseContext(void *hProv, int dwFlags);
int CryptCreateHash(void *hProv, int Algid, void *hKey, int dwFlags, void *phHash);
int CryptHashData(void *hHash, void *pbData, int dwDataLen, int dwFlags);
int CryptGetHashParam(void *hHash, int dwParam, void *pbData, void *pdwDataLen, int dwFlags);
int CryptDestroyHash(void *hHash);
int CryptDeriveKey(void *hProv, int Algid, void *hBaseData, int dwFlags, void *phKey);
int CryptGenKey(void *hProv, int Algid, int dwFlags, void *phKey);
int CryptImportKey(void *hProv, void *pbData, int dwDataLen, void *hPubKey, int dwFlags, void *phKey);
int CryptExportKey(void *hKey, void *hExpKey, int dwBlobType, int dwFlags, void *pbData, void *pdwDataLen);
int CryptEncrypt(void *hKey, void *hHash, int Final, int dwFlags, void *pbData, void *pdwDataLen, int dwBufLen);
int CryptDecrypt(void *hKey, void *hHash, int Final, int dwFlags, void *pbData, void *pdwDataLen);
int CryptDestroyKey(void *hKey);
int CryptVerifySignatureA(void *hHash, void *pbSignature, int dwSigLen, void *hPubKey, char *sDescription, int dwFlags);

/* BCrypt (Modern CNG) */
int BCryptOpenAlgorithmProvider(void *phAlgorithm, void *pszAlgId, void *pszImplementation, int dwFlags);
int BCryptCloseAlgorithmProvider(void *hAlgorithm, int dwFlags);
int BCryptCreateHash(void *hAlgorithm, void *phHash, void *pbHashObject, int cbHashObject, void *pbSecret, int cbSecret, int dwFlags);
int BCryptHashData(void *hHash, void *pbInput, int cbInput, int dwFlags);
int BCryptFinishHash(void *hHash, void *pbOutput, int cbOutput, int dwFlags);
int BCryptDestroyHash(void *hHash);
int BCryptEncrypt(void *hKey, void *pbInput, int cbInput, void *pPaddingInfo, void *pbIV, int cbIV, void *pbOutput, int cbOutput, void *pcbResult, int dwFlags);
int BCryptDecrypt(void *hKey, void *pbInput, int cbInput, void *pPaddingInfo, void *pbIV, int cbIV, void *pbOutput, int cbOutput, void *pcbResult, int dwFlags);
int BCryptGenerateSymmetricKey(void *hAlgorithm, void *phKey, void *pbKeyObject, int cbKeyObject, void *pbSecret, int cbSecret, int dwFlags);
int BCryptDestroyKey(void *hKey);

/* ============================================================================
 * Named Pipes / IPC
 * ============================================================================ */

void *CreateNamedPipeA(char *lpName, int dwOpenMode, int dwPipeMode, int nMaxInstances, int nOutBufSize, int nInBufSize, int nDefaultTimeOut, void *lpSecurityAttributes);
void *CreateNamedPipeW(void *lpName, int dwOpenMode, int dwPipeMode, int nMaxInstances, int nOutBufSize, int nInBufSize, int nDefaultTimeOut, void *lpSecurityAttributes);
int ConnectNamedPipe(void *hNamedPipe, void *lpOverlapped);
int DisconnectNamedPipe(void *hNamedPipe);
int CreatePipe(void *hReadPipe, void *hWritePipe, void *lpPipeAttributes, int nSize);
int SetNamedPipeHandleState(void *hNamedPipe, void *lpMode, void *lpMaxCollectionCount, void *lpCollectDataTimeout);
int PeekNamedPipe(void *hNamedPipe, void *lpBuffer, int nBufferSize, void *lpBytesRead, void *lpTotalBytesAvail, void *lpBytesLeftThisMessage);
int TransactNamedPipe(void *hNamedPipe, void *lpInBuffer, int nInBufferSize, void *lpOutBuffer, int nOutBufferSize, void *lpBytesRead, void *lpOverlapped);
int WaitNamedPipeA(char *lpNamedPipeName, int nTimeOut);

/* ============================================================================
 * Service Control Manager
 * ============================================================================ */

void *OpenSCManagerA(char *lpMachineName, char *lpDatabaseName, int dwDesiredAccess);
void *OpenSCManagerW(void *lpMachineName, void *lpDatabaseName, int dwDesiredAccess);
void *CreateServiceA(void *hSCManager, char *lpServiceName, char *lpDisplayName, int dwDesiredAccess, int dwServiceType, int dwStartType, int dwErrorControl, char *lpBinaryPathName, char *lpLoadOrderGroup, void *lpdwTagId, char *lpDependencies, char *lpServiceStartName, char *lpPassword);
void *CreateServiceW(void *hSCManager, void *lpServiceName, void *lpDisplayName, int dwDesiredAccess, int dwServiceType, int dwStartType, int dwErrorControl, void *lpBinaryPathName, void *lpLoadOrderGroup, void *lpdwTagId, void *lpDependencies, void *lpServiceStartName, void *lpPassword);
void *OpenServiceA(void *hSCManager, char *lpServiceName, int dwDesiredAccess);
void *OpenServiceW(void *hSCManager, void *lpServiceName, int dwDesiredAccess);
int StartServiceA(void *hService, int dwNumServiceArgs, void *lpServiceArgVectors);
int StartServiceW(void *hService, int dwNumServiceArgs, void *lpServiceArgVectors);
int ControlService(void *hService, int dwControl, void *lpServiceStatus);
int DeleteService(void *hService);
int ChangeServiceConfigA(void *hService, int dwServiceType, int dwStartType, int dwErrorControl, char *lpBinaryPathName, char *lpLoadOrderGroup, void *lpdwTagId, char *lpDependencies, char *lpServiceStartName, char *lpPassword, char *lpDisplayName);
int CloseServiceHandle(void *hSCObject);
int QueryServiceStatus(void *hService, void *lpServiceStatus);

/* ============================================================================
 * WinHTTP / WinInet (extended)
 * ============================================================================ */

void *WinHttpOpen(void *pszAgentW, int dwAccessType, void *pszProxyW, void *pszProxyBypassW, int dwFlags);
void *WinHttpConnect(void *hSession, void *pswzServerName, int nServerPort, int dwReserved);
void *WinHttpOpenRequest(void *hConnect, void *pwszVerb, void *pwszObjectName, void *pwszVersion, void *pwszReferrer, void *ppwszAcceptTypes, int dwFlags);
int WinHttpSendRequest(void *hRequest, void *pwszHeaders, int dwHeadersLength, void *lpOptional, int dwOptionalLength, int dwTotalLength, int dwContext);
int WinHttpReceiveResponse(void *hRequest, void *lpReserved);
int WinHttpReadData(void *hRequest, void *lpBuffer, int dwNumberOfBytesToRead, void *lpdwNumberOfBytesRead);
int WinHttpQueryHeaders(void *hRequest, int dwInfoLevel, void *pwszName, void *lpBuffer, void *lpdwBufferLength, void *lpdwIndex);
int WinHttpCloseHandle(void *hInternet);
void *InternetOpenA(char *lpszAgent, int dwAccessType, char *lpszProxy, char *lpszProxyBypass, int dwFlags);
void *InternetConnectA(void *hInternet, char *lpszServerName, int nServerPort, char *lpszUserName, char *lpszPassword, int dwService, int dwFlags, int dwContext);
void *HttpOpenRequestA(void *hConnect, char *lpszVerb, char *lpszObjectName, char *lpszVersion, char *lpszReferrer, void *lplpszAcceptTypes, int dwFlags, int dwContext);
int HttpSendRequestA(void *hRequest, char *lpszHeaders, int dwHeadersLength, void *lpOptional, int dwOptionalLength);

/* ============================================================================
 * Process Injection / Memory
 * ============================================================================ */

void *VirtualAllocEx(void *hProcess, void *lpAddress, int dwSize, int flAllocationType, int flProtect);
int VirtualFreeEx(void *hProcess, void *lpAddress, int dwSize, int dwFreeType);
int WriteProcessMemory(void *hProcess, void *lpBaseAddress, void *lpBuffer, int nSize, void *lpNumberOfBytesWritten);
int ReadProcessMemory(void *hProcess, void *lpBaseAddress, void *lpBuffer, int nSize, void *lpNumberOfBytesRead);
void *CreateRemoteThread(void *hProcess, void *lpThreadAttributes, int dwStackSize, void *lpStartAddress, void *lpParameter, int dwCreationFlags, void *lpThreadId);
int QueueUserAPC(void *pfnAPC, void *hThread, int dwData);
void *OpenProcess(int dwDesiredAccess, int bInheritHandle, int dwProcessId);

/* ============================================================================
 * Token / Impersonation
 * ============================================================================ */

int OpenProcessToken(void *ProcessHandle, int DesiredAccess, void *TokenHandle);
int OpenThreadToken(void *ThreadHandle, int DesiredAccess, int OpenAsSelf, void *TokenHandle);
int AdjustTokenPrivileges(void *TokenHandle, int DisableAllPrivileges, void *NewState, int BufferLength, void *PreviousState, void *ReturnLength);
int ImpersonateLoggedOnUser(void *hToken);
int RevertToSelf(void);
int DuplicateToken(void *ExistingTokenHandle, int ImpersonationLevel, void *DuplicateTokenHandle);
int DuplicateTokenEx(void *hExistingToken, int dwDesiredAccess, void *lpTokenAttributes, int ImpersonationLevel, int TokenType, void *phNewToken);
int LogonUserA(char *lpszUsername, char *lpszDomain, char *lpszPassword, int dwLogonType, int dwLogonProvider, void *phToken);
int LogonUserW(void *lpszUsername, void *lpszDomain, void *lpszPassword, int dwLogonType, int dwLogonProvider, void *phToken);
