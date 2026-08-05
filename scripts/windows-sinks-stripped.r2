# windows-sinks-stripped.r2 — Comment-stripped version of windows-sinks.r2
#
# Identical functionality to windows-sinks.r2 but without the documentation
# header. Faster to source in automated sessions where the comments add overhead.
# See windows-sinks.r2 for full documentation on what each sink category means.
#
# Sourced by: windows-x64.r2 and windows-x86.r2 profiles (via windows-sinks.r2
# which r2 loads from ~/.local/share/radare2/scripts/windows-sinks.r2).
# Use windows-sinks.r2 for interactive/manual use; use this file for
# embedding in pipelines where startup time matters.
#
# Usage:
#   . ~/.local/share/radare2/scripts/windows-sinks-stripped.r2
#   f~sink     — list all flagged dangerous sinks
#   f~entry    — list detected PE entry points

(sink n c r; s `ii~$0~[1]`; f sink.$0.iat @ $$; f sink.$0 @ `axt $$~jmp~[1]`; CC "$1:$2" @ $$)
?l `ii~WinExec~[1]`
?ne .(sink WinExec CMD runs-command-string-directly)
?l `ii~CreateProcessA~[1]`
?ne .(sink CreateProcessA CMD check-lpCommandLine-source)
?l `ii~CreateProcessW~[1]`
?ne .(sink CreateProcessW CMD check-lpCommandLine-source)
?l `ii~CreateProcessAsUserA~[1]`
?ne .(sink CreateProcessAsUserA CMD privilege-escalation-risk)
?l `ii~CreateProcessAsUserW~[1]`
?ne .(sink CreateProcessAsUserW CMD privilege-escalation-risk)
?l `ii~ShellExecuteA~[1]`
?ne .(sink ShellExecuteA CMD shell-path-injection)
?l `ii~ShellExecuteW~[1]`
?ne .(sink ShellExecuteW CMD shell-path-injection)
?l `ii~ShellExecuteExA~[1]`
?ne .(sink ShellExecuteExA CMD shell-path-injection)
?l `ii~ShellExecuteExW~[1]`
?ne .(sink ShellExecuteExW CMD shell-path-injection)
?l `ii~system~[1]`
?ne .(sink system CMD CRT-system-shell-injection)
?l `ii~_wsystem~[1]`
?ne .(sink _wsystem CMD CRT-wsystem-shell-injection)
?l `ii~popen~[1]`
?ne .(sink popen CMD pipe-exec-shell-injection)
?l `ii~_popen~[1]`
?ne .(sink _popen CMD pipe-exec-shell-injection)
?l `ii~_wpopen~[1]`
?ne .(sink _wpopen CMD wide-pipe-exec-injection)
?l `ii~LoadLibraryA~[1]`
?ne .(sink LoadLibraryA LOAD DLL-hijacking-if-path-controlled)
?l `ii~LoadLibraryW~[1]`
?ne .(sink LoadLibraryW LOAD DLL-hijacking-if-path-controlled)
?l `ii~LoadLibraryExA~[1]`
?ne .(sink LoadLibraryExA LOAD DLL-hijacking-check-flags)
?l `ii~LoadLibraryExW~[1]`
?ne .(sink LoadLibraryExW LOAD DLL-hijacking-check-flags)
?l `ii~WriteProcessMemory~[1]`
?ne .(sink WriteProcessMemory LOAD remote-process-code-injection)
?l `ii~CreateRemoteThread~[1]`
?ne .(sink CreateRemoteThread LOAD thread-injection-into-remote-process)
?l `ii~CreateRemoteThreadEx~[1]`
?ne .(sink CreateRemoteThreadEx LOAD thread-injection-into-remote-process)
?l `ii~VirtualAllocEx~[1]`
?ne .(sink VirtualAllocEx LOAD alloc-in-remote-process-for-injection)
?l `ii~VirtualAlloc~[1]`
?ne .(sink VirtualAlloc LOAD RWX-page-shellcode-staging)
?l `ii~VirtualProtect~[1]`
?ne .(sink VirtualProtect LOAD W^X-bypass-make-page-executable)
?l `ii~NtAllocateVirtualMemory~[1]`
?ne .(sink NtAllocateVirtualMemory LOAD NT-alloc-shellcode-staging)
?l `ii~NtWriteVirtualMemory~[1]`
?ne .(sink NtWriteVirtualMemory LOAD NT-remote-memory-write)
?l `ii~SetWindowsHookExA~[1]`
?ne .(sink SetWindowsHookExA LOAD global-hook-keylogger-injection)
?l `ii~SetWindowsHookExW~[1]`
?ne .(sink SetWindowsHookExW LOAD global-hook-keylogger-injection)
?l `ii~strcpy~[1]`
?ne .(sink strcpy COPY unbounded-copy-stack-overflow)
?l `ii~strcat~[1]`
?ne .(sink strcat COPY unbounded-concat-stack-overflow)
?l `ii~wcscpy~[1]`
?ne .(sink wcscpy COPY wchar-unbounded-copy)
?l `ii~wcscat~[1]`
?ne .(sink wcscat COPY wchar-unbounded-concat)
?l `ii~lstrcpyA~[1]`
?ne .(sink lstrcpyA COPY Win32-unbounded-copy)
?l `ii~lstrcpyW~[1]`
?ne .(sink lstrcpyW COPY Win32-unbounded-copy)
?l `ii~lstrcatA~[1]`
?ne .(sink lstrcatA COPY Win32-unbounded-concat)
?l `ii~lstrcatW~[1]`
?ne .(sink lstrcatW COPY Win32-unbounded-concat)
?l `ii~StrCpyA~[1]`
?ne .(sink StrCpyA COPY shlwapi-unbounded-copy)
?l `ii~StrCpyW~[1]`
?ne .(sink StrCpyW COPY shlwapi-unbounded-copy)
?l `ii~gets~[1]`
?ne .(sink gets COPY no-bounds-classic-BOF)
?l `ii~memcpy~[1]`
?ne .(sink memcpy COPY check-size-arg-for-overflow)
?l `ii~memmove~[1]`
?ne .(sink memmove COPY check-size-arg-for-overflow)
?l `ii~RtlCopyMemory~[1]`
?ne .(sink RtlCopyMemory COPY check-length-arg)
?l `ii~RtlMoveMemory~[1]`
?ne .(sink RtlMoveMemory COPY check-length-arg)
?l `ii~sprintf~[1]`
?ne .(sink sprintf FMT no-bounds-and-format-string)
?l `ii~vsprintf~[1]`
?ne .(sink vsprintf FMT no-bounds-and-format-string)
?l `ii~swprintf~[1]`
?ne .(sink swprintf FMT wchar-format-string)
?l `ii~vswprintf~[1]`
?ne .(sink vswprintf FMT wchar-format-string)
?l `ii~wsprintf~[1]`
?ne .(sink wsprintf FMT Win32-sprintf-format-string)
?l `ii~wvsprintf~[1]`
?ne .(sink wvsprintf FMT Win32-vsprintf-format-string)
?l `ii~_snprintf~[1]`
?ne .(sink _snprintf FMT off-by-one-no-null-guarantee)
?l `ii~vsnprintf~[1]`
?ne .(sink vsnprintf FMT check-format-string-arg)
?l `ii~printf~[1]`
?ne .(sink printf FMT format-string-if-arg1-user-controlled)
?l `ii~fprintf~[1]`
?ne .(sink fprintf FMT format-string-check-format-arg)
?l `ii~recv~[1]`
?ne .(sink recv NET TCP-receive-trace-forward-to-parser)
?l `ii~recvfrom~[1]`
?ne .(sink recvfrom NET UDP-receive-trace-forward-to-parser)
?l `ii~WSARecv~[1]`
?ne .(sink WSARecv NET overlapped-receive-async-network-input)
?l `ii~WSARecvFrom~[1]`
?ne .(sink WSARecvFrom NET overlapped-UDP-receive)
?l `ii~InternetReadFile~[1]`
?ne .(sink InternetReadFile NET HTTP-read-web-content-into-buffer)
?l `ii~HttpSendRequestA~[1]`
?ne .(sink HttpSendRequestA NET HTTP-request-SSRF-header-injection)
?l `ii~HttpSendRequestW~[1]`
?ne .(sink HttpSendRequestW NET HTTP-request-SSRF-header-injection)
?l `ii~WinHttpReadData~[1]`
?ne .(sink WinHttpReadData NET WinHTTP-receive-check-buffer-size)
?l `ii~WinHttpReceiveResponse~[1]`
?ne .(sink WinHttpReceiveResponse NET WinHTTP-response-check-sizes)
?l `ii~InternetOpenUrlA~[1]`
?ne .(sink InternetOpenUrlA NET SSRF-open-URL-user-controlled)
?l `ii~InternetOpenUrlW~[1]`
?ne .(sink InternetOpenUrlW NET SSRF-open-URL-user-controlled)
?l `ii~malloc~[1]`
?ne .(sink malloc HEAP check-size-arithmetic-before-call)
?l `ii~calloc~[1]`
?ne .(sink calloc HEAP check-nmemb-times-size-overflow)
?l `ii~realloc~[1]`
?ne .(sink realloc HEAP integer-overflow-in-new-size)
?l `ii~HeapAlloc~[1]`
?ne .(sink HeapAlloc HEAP check-dwBytes-arithmetic)
?l `ii~HeapReAlloc~[1]`
?ne .(sink HeapReAlloc HEAP integer-overflow-in-size)
?l `ii~LocalAlloc~[1]`
?ne .(sink LocalAlloc HEAP check-uBytes-arithmetic)
?l `ii~GlobalAlloc~[1]`
?ne .(sink GlobalAlloc HEAP check-uBytes-arithmetic)
?l `ii~CoTaskMemAlloc~[1]`
?ne .(sink CoTaskMemAlloc HEAP COM-alloc-check-size)
?l `ii~CryptEncrypt~[1]`
?ne .(sink CryptEncrypt CRYPT no-integrity-ciphertext-manipulation)
?l `ii~CryptDecrypt~[1]`
?ne .(sink CryptDecrypt CRYPT no-integrity-padding-oracle-risk)
?l `ii~BCryptEncrypt~[1]`
?ne .(sink BCryptEncrypt CRYPT check-auth-tag-if-GCM-mode)
?l `ii~BCryptDecrypt~[1]`
?ne .(sink BCryptDecrypt CRYPT check-auth-tag-if-GCM-mode)
?l `ii~RegSetValueExA~[1]`
?ne .(sink RegSetValueExA REG registry-write-check-data-source)
?l `ii~RegSetValueExW~[1]`
?ne .(sink RegSetValueExW REG registry-write-check-data-source)
?l `ii~RegCreateKeyExA~[1]`
?ne .(sink RegCreateKeyExA REG registry-key-create-check-path)
?l `ii~RegCreateKeyExW~[1]`
?ne .(sink RegCreateKeyExW REG registry-key-create-check-path)
?l `ii~LogonUserA~[1]`
?ne .(sink LogonUserA AUTH check-error-path-cred-stuffing-target)
?l `ii~LogonUserW~[1]`
?ne .(sink LogonUserW AUTH check-error-path-cred-stuffing-target)
?l `ii~CryptVerifySignature~[1]`
?ne .(sink CryptVerifySignature AUTH verify-return-value-auth-bypass)
?l `ii~OpenSCManagerA~[1]`
?ne .(sink OpenSCManagerA SCM opens-service-control-manager)
?l `ii~OpenSCManagerW~[1]`
?ne .(sink OpenSCManagerW SCM opens-service-control-manager)
?l `ii~CreateServiceA~[1]`
?ne .(sink CreateServiceA SCM creates-persistent-service-persistence)
?l `ii~CreateServiceW~[1]`
?ne .(sink CreateServiceW SCM creates-persistent-service-persistence)
?l `ii~ChangeServiceConfigA~[1]`
?ne .(sink ChangeServiceConfigA SCM modifies-service-binary-path)
?l `ii~ChangeServiceConfigW~[1]`
?ne .(sink ChangeServiceConfigW SCM modifies-service-binary-path)
?l `ii~CreateNamedPipeA~[1]`
?ne .(sink CreateNamedPipeA PIPE creates-named-pipe-server)
?l `ii~CreateNamedPipeW~[1]`
?ne .(sink CreateNamedPipeW PIPE creates-named-pipe-server)
?l `ii~ConnectNamedPipe~[1]`
?ne .(sink ConnectNamedPipe PIPE accepts-named-pipe-connection)
?l `ii~ReadProcessMemory~[1]`
?ne .(sink ReadProcessMemory INJECTION reads-remote-process-memory)
?l `ii~QueueUserAPC~[1]`
?ne .(sink QueueUserAPC INJECTION queues-apc-code-injection)
?l `ii~OpenProcessToken~[1]`
?ne .(sink OpenProcessToken TOKEN opens-process-token)
?l `ii~AdjustTokenPrivileges~[1]`
?ne .(sink AdjustTokenPrivileges TOKEN adjusts-privileges-privesc)
?l `ii~ImpersonateLoggedOnUser~[1]`
?ne .(sink ImpersonateLoggedOnUser TOKEN impersonates-user-token)
?l `ii~DuplicateTokenEx~[1]`
?ne .(sink DuplicateTokenEx TOKEN duplicates-token-for-impersonation)
?l `ii~WinHttpOpen~[1]`
?ne .(sink WinHttpOpen NET opens-winhttp-session)
?l `ii~WinHttpConnect~[1]`
?ne .(sink WinHttpConnect NET connects-to-server-via-winhttp)
?l `ii~WinHttpOpenRequest~[1]`
?ne .(sink WinHttpOpenRequest NET opens-winhttp-request)
?l `ii~WinHttpSendRequest~[1]`
?ne .(sink WinHttpSendRequest NET sends-winhttp-request)
?l `ii~CryptAcquireContextA~[1]`
?ne .(sink CryptAcquireContextA CRYPTO acquires-crypto-provider)
?l `ii~CryptAcquireContextW~[1]`
?ne .(sink CryptAcquireContextW CRYPTO acquires-crypto-provider)
?l `ii~CryptCreateHash~[1]`
?ne .(sink CryptCreateHash CRYPTO creates-hash-object)
?l `ii~CryptHashData~[1]`
?ne .(sink CryptHashData CRYPTO hashes-data)
?l `ii~BCryptOpenAlgorithmProvider~[1]`
?ne .(sink BCryptOpenAlgorithmProvider CRYPTO opens-cng-algorithm)
?l `ii~BCryptGenerateSymmetricKey~[1]`
?ne .(sink BCryptGenerateSymmetricKey CRYPTO generates-symmetric-key)

?l `afl~WinMain~[0]`
?ne f entry.WinMain @ `afl~WinMain~[2]`
?l `afl~DllMain~[0]`
?ne f entry.DllMain @ `afl~DllMain~[2]`
?l `afl~wmain~[0]`
?ne f entry.wmain @ `afl~wmain~[2]`
?l `afl~_tmain~[0]`
?ne f entry._tmain @ `afl~_tmain~[2]`
?l `afl~mainCRTStartup~[0]`
?ne f entry.CRTStartup @ `afl~mainCRTStartup~[2]`
?l `afl~TlsCallback~[0]`
?ne f entry.TlsCallback @ `afl~TlsCallback~[2]`
?l `iT~callback~[1]`
?ne f entry.TLS_callback @ `iT~callback~[1]`
?e [win-sinks] Sink labeling complete.
?e [win-sinks]   f~sink   — list all dangerous import flags
?e [win-sinks]   f~entry  — list detected entry points
?e [win-sinks]   axt sink.FUNCNAME — find all callers of a sink
