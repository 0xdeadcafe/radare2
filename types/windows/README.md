# Windows SDK Type Definitions for radare2

Type definitions for Windows API analysis.

## Files

| File | Contents |
|------|----------|
| `winerror.h` | Win32 error codes (ERROR_*), HRESULT values |
| `ntstatus.h` | NT status codes (STATUS_*) |
| `structs.h` | Common Win32/NT structs (OVERLAPPED, SECURITY_ATTRIBUTES, etc.) |
| `constants.h` | API constants (PAGE_*, MEM_*, PROCESS_*, FILE_*, etc.) |
| `functions.h` | Win32 API function signatures |

## Usage

```r2
# Load Windows types
to types/windows/winerror.h
to types/windows/ntstatus.h
to types/windows/structs.h
to types/windows/constants.h
to types/windows/functions.h

# Look up error code
te win32_error 5          # ERROR_ACCESS_DENIED

# Look up NTSTATUS
te ntstatus 0xC0000005    # STATUS_ACCESS_VIOLATION

# Show memory protection values
te win_page_protect

# Show function signature
tfc CreateFileA
tfc VirtualAlloc

# Apply struct to memory
tp OVERLAPPED @ 0x1000
tp PROCESS_INFORMATION @ 0x2000
```

## Quick Reference

### Common Win32 Errors
```
ERROR_SUCCESS = 0
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_NOT_ENOUGH_MEMORY = 8
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MOD_NOT_FOUND = 126
ERROR_PROC_NOT_FOUND = 127
```

### Common NTSTATUS Codes
```
STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_DLL_NOT_FOUND = 0xC0000135
STATUS_ENTRYPOINT_NOT_FOUND = 0xC0000139
```

### Memory Protection
```
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
```

### Process Access Rights
```
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_ALL_ACCESS = 0x1FFFFF
```

## Architecture Notes

Struct definitions are for **x64 Windows**:
- Pointers/HANDLEs are 8 bytes
- LONG is 4 bytes (LLP64 model)
- Some structs have different layouts on x86

For x86 analysis, pointer fields would be 4 bytes instead of 8.

## Combining with zsigs

```r2
# Load Windows x64 signatures
zo zigns/windows/x64/vs2022-vcruntime140.zsig
zo zigns/windows/x64/winsdk-libucrt.zsig

# Load type information (both standard and zsig variants)
to types/windows/functions.h
to types/windows/functions-zsig.h
to types/windows/winerror.h

# Analyze
aaa
z/
aaft  # Apply types to zsig-matched functions
```

## Files

| File | Contents |
|------|----------|
| `winerror.h` | Win32 error codes (ERROR_*), HRESULT values |
| `ntstatus.h` | NT status codes (STATUS_*) |
| `structs.h` | Common Win32/NT structs (OVERLAPPED, SECURITY_ATTRIBUTES, etc.) |
| `constants.h` | API constants (PAGE_*, MEM_*, PROCESS_*, FILE_*, etc.) |
| `functions.h` | Win32 API function signatures |
| `functions-zsig.h` | MSVC CRT zsig variants (_malloc, _beginthread, etc.) |

## Zsig Type Matching

The `functions-zsig.h` file provides type definitions for MSVC CRT functions
that use underscore-prefixed names (`_malloc`, `_free`, `_beginthread`, etc.).
These match the function names produced by zsig matching.
