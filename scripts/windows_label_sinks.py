#!/usr/bin/env python3
"""
windows_label_sinks.py — Auto-label Windows PE security sinks and entry points.

Run inside an r2 session as:
    #!python ~/.local/share/radare2/scripts/windows_label_sinks.py

What this script does
─────────────────────
1.  Iterates the PE import table (iij).
2.  For every import whose name appears in the SINKS table, creates an r2 flag:
        f sink.<name> @ <plt_addr>
    and adds an annotation:
        CC "<SINK_CLASS>: <reason>" @ <plt_addr>
3.  Looks for known entry-point patterns in the function list (WinMain, DllMain,
    TLS callbacks, _tmain, wmain) and flags them as entry.<name>.
4.  Applies loaded type definitions to known import addresses (tfc + aft).
5.  Prints a one-line summary of what was labeled.

Sink categories
───────────────
  CMD   — direct command/code execution (WinExec, ShellExecute, CreateProcess…)
  LOAD  — DLL injection / code loading (LoadLibrary, WriteProcessMemory…)
  COPY  — unsafe string/memory copy (strcpy, lstrcpy, sprintf, wsprintf…)
  FMT   — format string function (printf-family with user-controlled format)
  NET   — socket / network receive (recv, WSARecv, recvfrom…)
  HEAP  — allocator that can be overflowed into (malloc / HeapAlloc variants)
  CRYPT — weak/unauthenticated crypto (CryptEncrypt without integrity, RC4…)
  REG   — registry write that persists attacker data
  AUTH  — authentication check that can be bypassed
"""

import json
import sys
import re

# ─────────────────────────────────────────────────────────────────────────────
# Sink table  — (category, brief reason)
# Keys are exact import names as they appear in the PE IAT / rabin2 output.
# ─────────────────────────────────────────────────────────────────────────────

SINKS: dict[str, tuple[str, str]] = {
    # ── CMD — command/process execution ──────────────────────────────────────
    "WinExec":                    ("CMD", "runs cmd string; no shell escape"),
    "CreateProcessA":             ("CMD", "creates process; lpCommandLine user-controlled?"),
    "CreateProcessW":             ("CMD", "creates process; lpCommandLine user-controlled?"),
    "CreateProcessAsUserA":       ("CMD", "creates process as user; privilege escalation risk"),
    "CreateProcessAsUserW":       ("CMD", "creates process as user; privilege escalation risk"),
    "ShellExecuteA":              ("CMD", "shell exec; parameter injection risk"),
    "ShellExecuteW":              ("CMD", "shell exec; parameter injection risk"),
    "ShellExecuteExA":            ("CMD", "shell exec extended; parameter injection risk"),
    "ShellExecuteExW":            ("CMD", "shell exec extended; parameter injection risk"),
    "system":                     ("CMD", "CRT system(); trivial command injection"),
    "_wsystem":                   ("CMD", "wide-char system(); trivial command injection"),
    "popen":                      ("CMD", "pipe + exec; command injection"),
    "_popen":                     ("CMD", "pipe + exec; command injection"),
    "_wpopen":                    ("CMD", "wide-char popen; command injection"),

    # ── LOAD — code loading / injection ──────────────────────────────────────
    "LoadLibraryA":               ("LOAD", "load DLL by path; DLL hijacking / injection"),
    "LoadLibraryW":               ("LOAD", "load DLL by path; DLL hijacking / injection"),
    "LoadLibraryExA":             ("LOAD", "load DLL with flags; DLL hijacking"),
    "LoadLibraryExW":             ("LOAD", "load DLL with flags; DLL hijacking"),
    "WriteProcessMemory":         ("LOAD", "write to remote process; code injection"),
    "CreateRemoteThread":         ("LOAD", "create thread in remote process; code injection"),
    "CreateRemoteThreadEx":       ("LOAD", "create thread in remote process; code injection"),
    "VirtualAllocEx":             ("LOAD", "alloc in remote process; staging for injection"),
    "NtCreateThread":             ("LOAD", "NT create thread; code injection"),
    "NtWriteVirtualMemory":       ("LOAD", "NT write memory; code injection"),
    "RtlCreateUserThread":        ("LOAD", "Rtl create thread; code injection"),
    "SetWindowsHookExA":          ("LOAD", "global hook; keylogger / injection vector"),
    "SetWindowsHookExW":          ("LOAD", "global hook; keylogger / injection vector"),

    # ── COPY — unsafe buffer copy ─────────────────────────────────────────────
    "strcpy":                     ("COPY", "unbounded string copy; classic stack overflow"),
    "strcat":                     ("COPY", "unbounded string concat; stack overflow"),
    "wcscpy":                     ("COPY", "wide-char unbounded copy; stack overflow"),
    "wcscat":                     ("COPY", "wide-char unbounded concat; stack overflow"),
    "lstrcpyA":                   ("COPY", "Win32 unbounded copy; stack overflow"),
    "lstrcpyW":                   ("COPY", "Win32 unbounded copy; stack overflow"),
    "lstrcatA":                   ("COPY", "Win32 unbounded concat; stack overflow"),
    "lstrcatW":                   ("COPY", "Win32 unbounded concat; stack overflow"),
    "StrCpyA":                    ("COPY", "Shlwapi unbounded copy; stack overflow"),
    "StrCpyW":                    ("COPY", "Shlwapi unbounded copy; stack overflow"),
    "StrCatA":                    ("COPY", "Shlwapi unbounded concat; stack overflow"),
    "StrCatW":                    ("COPY", "Shlwapi unbounded concat; stack overflow"),
    "gets":                       ("COPY", "reads until newline; stack overflow"),
    "memcpy":                     ("COPY", "size-unvalidated memcpy; heap/stack overflow"),
    "memmove":                    ("COPY", "size-unvalidated memmove; overflow"),
    "CopyMemory":                 ("COPY", "size-unvalidated CopyMemory macro"),
    "RtlCopyMemory":              ("COPY", "size-unvalidated RtlCopyMemory; overflow"),
    "RtlMoveMemory":              ("COPY", "size-unvalidated RtlMoveMemory; overflow"),
    "ZeroMemory":                 ("COPY", "if size is wrong can zero past buffer"),

    # ── FMT — format string ───────────────────────────────────────────────────
    "sprintf":                    ("FMT",  "no bounds check; stack overflow + format string"),
    "vsprintf":                   ("FMT",  "no bounds check; stack overflow + format string"),
    "swprintf":                   ("FMT",  "wide-char sprintf; stack overflow"),
    "vswprintf":                  ("FMT",  "wide-char vsprintf; stack overflow"),
    "wsprintf":                   ("FMT",  "Win32 sprintf; stack overflow + format string"),
    "wvsprintf":                  ("FMT",  "Win32 vsprintf; stack overflow + format string"),
    "printf":                     ("FMT",  "format string if arg1 is user-controlled"),
    "fprintf":                    ("FMT",  "format string if format arg is user-controlled"),
    "wprintf":                    ("FMT",  "wide-char printf; format string"),
    "_snprintf":                  ("FMT",  "off-by-one risk; no null termination guarantee"),
    "StringCbPrintfA":            ("FMT",  "safe but verify format string source"),
    "StringCbPrintfW":            ("FMT",  "safe but verify format string source"),

    # ── NET — network receive ─────────────────────────────────────────────────
    "recv":                       ("NET",  "TCP receive; entry point for network input"),
    "recvfrom":                   ("NET",  "UDP receive; entry point for network input"),
    "WSARecv":                    ("NET",  "overlapped receive; entry point for net input"),
    "WSARecvFrom":                ("NET",  "overlapped UDP receive; net input entry"),
    "ReadFile":                   ("NET",  "pipe/socket/file read; if handle is network"),
    "InternetReadFile":           ("NET",  "HTTP read; web content into buffer"),
    "HttpSendRequestA":           ("NET",  "HTTP request; SSRF / header injection"),
    "HttpSendRequestW":           ("NET",  "HTTP request; SSRF / header injection"),
    "InternetOpenUrlA":           ("NET",  "open URL; SSRF / path traversal"),
    "InternetOpenUrlW":           ("NET",  "open URL; SSRF / path traversal"),
    "WinHttpReceiveResponse":     ("NET",  "WinHTTP receive; response injection risk"),
    "WinHttpReadData":            ("NET",  "WinHTTP read; web content into buffer"),

    # ── HEAP — allocators ────────────────────────────────────────────────────
    "malloc":                     ("HEAP", "check size arithmetic before call"),
    "calloc":                     ("HEAP", "check nmemb*size arithmetic before call"),
    "realloc":                    ("HEAP", "integer overflow in size arg risk"),
    "HeapAlloc":                  ("HEAP", "check dwBytes arithmetic before call"),
    "HeapReAlloc":                ("HEAP", "integer overflow in size arg risk"),
    "LocalAlloc":                 ("HEAP", "check uBytes arithmetic before call"),
    "GlobalAlloc":                ("HEAP", "check uBytes arithmetic before call"),
    "CoTaskMemAlloc":             ("HEAP", "COM allocator; check size arithmetic"),
    "VirtualAlloc":               ("HEAP", "map executable memory; used in shellcode"),
    "VirtualProtect":             ("HEAP", "set page permissions; W^X bypass"),
    "NtAllocateVirtualMemory":    ("HEAP", "NT alloc; shellcode staging"),

    # ── CRYPT — weak/risky crypto ────────────────────────────────────────────
    "CryptEncrypt":               ("CRYPT","no integrity; ciphertext manipulation risk"),
    "CryptDecrypt":               ("CRYPT","no integrity; padding oracle / CBC risk"),
    "CryptDeriveKey":             ("CRYPT","key derivation; check algorithm is modern"),
    "BCryptEncrypt":              ("CRYPT","check auth tag if GCM mode"),
    "BCryptDecrypt":              ("CRYPT","check auth tag if GCM mode"),

    # ── REG — registry write ─────────────────────────────────────────────────
    "RegSetValueExA":             ("REG",  "persists to registry; check data source"),
    "RegSetValueExW":             ("REG",  "persists to registry; check data source"),
    "RegCreateKeyExA":            ("REG",  "creates registry key; check path source"),
    "RegCreateKeyExW":            ("REG",  "creates registry key; check path source"),

    # ── AUTH — authentication ────────────────────────────────────────────────
    "LogonUserA":                 ("AUTH", "check error path; cred stuffing target"),
    "LogonUserW":                 ("AUTH", "check error path; cred stuffing target"),
    "CryptVerifySignature":       ("AUTH", "verify return value; auth bypass if ignored"),
    "CryptVerifySignatureA":      ("AUTH", "verify return value; auth bypass if ignored"),
    "CryptVerifySignatureW":      ("AUTH", "verify return value; auth bypass if ignored"),
}

# ─────────────────────────────────────────────────────────────────────────────
# Entry-point indicators — function names that indicate WinMain / DllMain /
# TLS callback patterns in the r2 function list.
# ─────────────────────────────────────────────────────────────────────────────

ENTRY_PATTERNS = [
    (r"^WinMain(CRTStartup)?$",  "entry.WinMain"),
    (r"^wWinMain(CRTStartup)?$", "entry.wWinMain"),
    (r"^DllMain(CRTStartup)?$",  "entry.DllMain"),
    (r"^_DllMainCRTStartup$",    "entry.DllMain"),
    (r"^__DllMainCRTStartup$",   "entry.DllMain"),
    (r"^mainCRTStartup$",        "entry.CRTStartup"),
    (r"^wmainCRTStartup$",       "entry.wCRTStartup"),
    (r"^_tmain$",                "entry.tmain"),
    (r"^wmain$",                 "entry.wmain"),
    (r"^TlsCallback_",           "entry.TLS_callback"),
    (r"^_tls_callback",          "entry.TLS_callback"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Main — runs inside the r2 session via #!python
# Connects back to the running r2 instance via r2pipe.open()
# ─────────────────────────────────────────────────────────────────────────────

def main():
    sink_count   = 0
    entry_count  = 0
    import_count = 0

    # Connect to the running r2 instance (r2pipe.open() with no args connects
    # to the parent r2 process via the #!pipe / lang_python mechanism)
    try:
        import r2pipe
        r2 = r2pipe.open()
    except Exception as e:
        print(f"[win-sinks] ERROR: could not open r2pipe: {e}", file=sys.stderr)
        return

    # ── 1. Get imports ────────────────────────────────────────────────────────
    try:
        imports_raw = r2.cmdj("iij") or []
    except Exception:
        imports_raw = []

    import_count = len(imports_raw)

    for imp in imports_raw:
        name = imp.get("name") or imp.get("realname") or ""
        plt  = imp.get("plt") or imp.get("bind") or 0

        # Strip leading/trailing underscores and module prefix (e.g. "KERNEL32_CreateFileA")
        clean = re.sub(r'^[_]+', '', name)
        module_sep = clean.find("_")
        # Only strip module prefix for known DLL names
        _known_modules = {
            "KERNEL32", "NTDLL", "USER32", "ADVAPI32", "MSVCRT",
            "UCRTBASE", "VCRUNTIME", "WS2_32", "WININET", "WINHTTP",
            "SHLWAPI", "SHELL32",
        }
        if module_sep > 0:
            candidate_module = clean[:module_sep].upper()
            if candidate_module in _known_modules:
                clean = clean[module_sep + 1:]

        if clean not in SINKS:
            # Try original name too
            if name not in SINKS:
                continue
            clean = name

        if not plt or plt == 0:
            continue

        category, reason = SINKS[clean]

        # Create sink flag at IAT address
        r2.cmd(f"f sink.{clean}.iat @ {plt}")

        # Add analysis comment at IAT
        r2.cmd(f'CC "{category}: {reason}" @ {plt}')

        # Find the wrapper stub: look for a JMP thunk that references this IAT entry.
        # For PE: IAT entry is at `plt`, the symbol table often has an entry like
        #   sym.imp.<dll>_<func>  at the same plt address.
        # The wrapper stub does: jmp [sym.imp.<dll>_<func>]
        # We find it by scanning xrefs of `plt` for JMP instructions.
        wrapper_addr = None
        try:
            xref_raw = r2.cmd(f"axtj {plt}").strip()
            xrefs = json.loads(xref_raw) if xref_raw else []
            for xr in xrefs:
                stub_addr = xr.get("from") or 0
                opcode = (xr.get("opcode") or "").lower()
                if stub_addr and ("jmp" in opcode or "call" in opcode):
                    wrapper_addr = stub_addr
                    r2.cmd(f"f sink.{clean} @ {stub_addr}")
                    r2.cmd(f'CC "{category}: {reason} [wrapper]" @ {stub_addr}')
                    break
        except Exception:
            pass

        # If no wrapper found, put the sink flag directly at the IAT
        if wrapper_addr is None:
            r2.cmd(f"f sink.{clean} @ {plt}")

        sink_count += 1

    # ── 2. Label known entry points from function list ────────────────────────
    try:
        funcs = r2.cmdj("aflj") or []
    except Exception:
        funcs = []

    for fn in funcs:
        fname = fn.get("name") or ""
        faddr = fn.get("offset") or fn.get("addr") or 0
        if not faddr:
            continue
        for pattern, flag_name in ENTRY_PATTERNS:
            if re.match(pattern, fname, re.IGNORECASE):
                r2.cmd(f"f {flag_name} @ {faddr}")
                entry_count += 1
                break

    # ── 3. Label TLS callbacks from data directory ────────────────────────────
    try:
        tls_raw = r2.cmd("iT").strip()
        for line in tls_raw.splitlines():
            m = re.search(r'callback.*?0x([0-9a-fA-F]+)', line, re.IGNORECASE)
            if m:
                cb_addr = int(m.group(1), 16)
                if cb_addr > 0:
                    r2.cmd(f"f entry.TLS_callback @ {cb_addr}")
                    entry_count += 1
    except Exception:
        pass

    # ── 4. Summary ───────────────────────────────────────────────────────────
    print(f"[win-sinks] {import_count} imports scanned: "
          f"{sink_count} sinks flagged, {entry_count} entry points labeled")
    print(f"[win-sinks] Use 'f~sink' to list sinks, 'f~entry' for entry points")


main()
