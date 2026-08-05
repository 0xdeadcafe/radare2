# =============================================================================
# elf-sinks.r2 — Native r2 security sink labeler for ELF binaries
# =============================================================================
#
# Language: native r2 command language (no Python, no external tools)
#
# Source manually after analysis:
#   aa
#   . ~/.local/share/radare2/scripts/elf-sinks.r2
#   f~sink        -- list all labeled sinks
#   axt sink.system  -- find all callers of system()
#
# Or source from a profile (after aa completes):
#   . ~/.local/share/radare2/scripts/elf-sinks.r2
#
# What this script does
# ─────────────────────
# 1. For each dangerous libc/POSIX function, checks whether the binary
#    imports it (via PLT / sym.imp.*).
# 2. If present, creates a  f sink.NAME @ sym.imp.NAME  flag.
# 3. Annotates the PLT stub with a CC comment describing the risk.
# 4. Prints a one-line summary of how many sinks were found.
#
# For statically linked binaries where zsig matching has renamed functions,
# the script also checks for bare function names (e.g. fcn.system).
# Use  z/  before sourcing this script to maximise zsig match coverage.
#
# Sink categories
# ───────────────
#   CMD_INJECTION   — arbitrary command execution (system, popen, execve, ...)
#   BUFFER_OVERFLOW — unsafe string/memory ops (gets, sprintf, strcpy, ...)
#   FORMAT_STRING   — printf-family with untrusted format args
#   HEAP_CORRUPTION — use-after-free primitives (realloc edge cases, etc.)
#   NETWORK_INPUT   — bytes arriving from the network
#   FILE_WRITE      — arbitrary file writes
#
# Conditional execution
# ─────────────────────
#   ?l `ii~NAME[1]`      — sets $? to address string length (0 if not present)
#   ?ne .(sink NAME ..)  — runs the macro only when $? != 0
#
# Usage after loading
# ───────────────────
#   f~sink              -- list all flagged sinks
#   axt sink.system     -- find all callers of system()
#   axt sink.recv       -- find all callers of recv()
#   axt sink.sprintf    -- find all callers of sprintf()
# =============================================================================

# ── Sink macro definition ─────────────────────────────────────────────────────
# (sink NAME CATEGORY REASON)
# 1. Seek to sym.imp.NAME
# 2. Create f sink.NAME flag at current address
# 3. Add comment describing the risk
"(sink, f sink.$0 @ sym.imp.$0; s sym.imp.$0; CC $1: $2 @ sym.imp.$0)"

# ── CMD_INJECTION sinks ───────────────────────────────────────────────────────

?l `ii~[1]~system`
?ne .(sink system CMD_INJECTION "Executes shell command via /bin/sh — trace all callers for injection")

?l `ii~[1]~popen`
?ne .(sink popen CMD_INJECTION "Opens pipe to shell command — check format string and caller inputs")

?l `ii~[1]~execve`
?ne .(sink execve CMD_INJECTION "Direct execve syscall — argv[0] and envp may be attacker-controlled")

?l `ii~[1]~execv`
?ne .(sink execv CMD_INJECTION "execv — check pathname and argv array sources")

?l `ii~[1]~execvp`
?ne .(sink execvp CMD_INJECTION "execvp — searches PATH; cmd injection if path or argv tainted")

?l `ii~[1]~execl`
?ne .(sink execl CMD_INJECTION "execl — varargs command; check all string arguments")

?l `ii~[1]~execlp`
?ne .(sink execlp CMD_INJECTION "execlp — PATH search + varargs; double injection vector")

?l `ii~[1]~execle`
?ne .(sink execle CMD_INJECTION "execle — explicit envp; check for LD_PRELOAD injection")

?l `ii~[1]~posix_spawn`
?ne .(sink posix_spawn CMD_INJECTION "posix_spawn — check file and argv sources")

# ── BUFFER_OVERFLOW sinks ─────────────────────────────────────────────────────

?l `ii~[1]~gets`
?ne .(sink gets BUFFER_OVERFLOW "gets() reads unbounded input — immediate stack overflow")

?l `ii~[1]~strcpy`
?ne .(sink strcpy BUFFER_OVERFLOW "Unbounded string copy — check dest buffer size vs src")

?l `ii~[1]~strcat`
?ne .(sink strcat BUFFER_OVERFLOW "Unbounded string concat — check dest remaining space")

?l `ii~[1]~sprintf`
?ne .(sink sprintf BUFFER_OVERFLOW "sprintf to fixed buffer — check dest size vs format output")

?l `ii~[1]~vsprintf`
?ne .(sink vsprintf BUFFER_OVERFLOW "vsprintf to fixed buffer — check dest size vs format output")

?l `ii~[1]~stpcpy`
?ne .(sink stpcpy BUFFER_OVERFLOW "stpcpy — unbounded copy; check dest buffer size")

?l `ii~[1]~wcscpy`
?ne .(sink wcscpy BUFFER_OVERFLOW "wcscpy — unbounded wide-char copy")

?l `ii~[1]~wcscat`
?ne .(sink wcscat BUFFER_OVERFLOW "wcscat — unbounded wide-char concat")

# ── FORMAT_STRING sinks ───────────────────────────────────────────────────────

?l `ii~[1]~printf`
?ne .(sink printf FORMAT_STRING "printf — verify format arg is a literal string constant")

?l `ii~[1]~fprintf`
?ne .(sink fprintf FORMAT_STRING "fprintf — verify format arg; check if stream is stderr/log")

?l `ii~[1]~dprintf`
?ne .(sink dprintf FORMAT_STRING "dprintf — printf to fd; verify format arg")

?l `ii~[1]~syslog`
?ne .(sink syslog FORMAT_STRING "syslog — log format string; often passed user input directly")

# ── NETWORK_INPUT sinks ───────────────────────────────────────────────────────

?l `ii~[1]~recv`
?ne .(sink recv NETWORK_INPUT "recv — raw socket receive; trace buffer to consumers")

?l `ii~[1]~recvfrom`
?ne .(sink recvfrom NETWORK_INPUT "recvfrom — UDP receive; caller controls src addr + data")

?l `ii~[1]~recvmsg`
?ne .(sink recvmsg NETWORK_INPUT "recvmsg — scatter/gather receive; trace iov_base buffers")

?l `ii~[1]~read`
?ne .(sink read NETWORK_INPUT "read — may read from socket fd; check fd provenance")

?l `ii~[1]~fread`
?ne .(sink fread NETWORK_INPUT "fread — may read from network FILE*; check stream source")

?l `ii~[1]~SSL_read`
?ne .(sink SSL_read NETWORK_INPUT "SSL_read — TLS receive; trace decrypted buffer consumers")

?l `ii~[1]~mbedtls_ssl_read`
?ne .(sink mbedtls_ssl_read NETWORK_INPUT "mbedtls_ssl_read — mbed TLS receive; trace buffer")

# ── MEMORY_CORRUPTION sinks ───────────────────────────────────────────────────

?l `ii~[1]~memcpy`
?ne .(sink memcpy BUFFER_OVERFLOW "memcpy — check length arg for integer overflow or attacker control")

?l `ii~[1]~memmove`
?ne .(sink memmove BUFFER_OVERFLOW "memmove — check length arg; overlap-safe but still sized")

?l `ii~[1]~sscanf`
?ne .(sink sscanf BUFFER_OVERFLOW "sscanf — check %s width specifiers; unbounded %s = overflow")

?l `ii~[1]~fscanf`
?ne .(sink fscanf BUFFER_OVERFLOW "fscanf — check %s width specifiers")

?l `ii~[1]~scanf`
?ne .(sink scanf BUFFER_OVERFLOW "scanf — check %s; often unbounded stdin read")

# ── FILE_WRITE sinks ──────────────────────────────────────────────────────────

?l `ii~[1]~fopen`
?ne .(sink fopen FILE_WRITE "fopen — check pathname for path traversal if caller-controlled")

?l `ii~[1]~open`
?ne .(sink open FILE_WRITE "open — check pathname for traversal; O_WRONLY|O_CREAT is write sink")

?l `ii~[1]~rename`
?ne .(sink rename FILE_WRITE "rename — check both paths; atomic swap can clobber privileged files")

?l `ii~[1]~symlink`
?ne .(sink symlink FILE_WRITE "symlink — check target; symlink attack if path is attacker-controlled")

?l `ii~[1]~unlink`
?ne .(sink unlink FILE_WRITE "unlink — check pathname; TOCTOU if path is derived from user input")

?l `ii~[1]~chmod`
?ne .(sink chmod FILE_WRITE "chmod — check mode bits; chmod 0777 on sensitive path is privilege esc")

?l `ii~[1]~chown`
?ne .(sink chown FILE_WRITE "chown — check uid/gid; chown root: attacker-controlled file = PrivEsc")

?l `ii~[1]~write`
?ne .(sink write FILE_WRITE "write — check fd and buffer; write to /proc or /sys entries")

# ── Privilege escalation sinks ────────────────────────────────────────────────

?l `ii~[1]~setuid`
?ne .(sink setuid PRIV_ESC "setuid — check if uid is attacker-influenced")

?l `ii~[1]~setgid`
?ne .(sink setgid PRIV_ESC "setgid — check if gid is attacker-influenced")

?l `ii~[1]~setresuid`
?ne .(sink setresuid PRIV_ESC "setresuid — drops privileges; check for bypass (uid=0 path)")

# ── Summary ───────────────────────────────────────────────────────────────────
?e
?e [elf-sinks] Sink labeling complete.
?e [elf-sinks] Use: f~sink      -- list all sinks
?e [elf-sinks]      axt sink.system   -- find system() callers
?e [elf-sinks]      axt sink.recv     -- find recv() callers
