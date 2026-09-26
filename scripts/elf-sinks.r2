# =============================================================================
# elf-sinks.r2 -- ELF security sink labeler for Linux / BSD / macOS binaries
# =============================================================================
#
# Language: native r2 command language (no Python, no external tools)
#
# Run AFTER aa:
#   aa
#   . ~/.local/share/radare2/scripts/elf-sinks.r2
#   f~sink           -- list all labeled sinks
#   axt sink.system  -- find callers of system()
#   axt sink.recv    -- find callers of recv()
#
# Mechanism: f sink.NAME @ sym.imp.NAME
#   r2 silently ignores non-existent symbols.
#   Commands are semicolon-chained on one logical line so that consecutive
#   "symbol not found" errors do not abort script execution (r2 6.x bug).
#
# After running, use:
#   f~sink           -- list all sinks (CMD_INJECTION / BUFFER_OVERFLOW / etc.)
#   axt sink.gets    -- cross-reference to dangerous sink
#   axt sink.printf  -- find format string locations
#   r2_vuln_scan     -- full xref-based scan from pi (covers all sink categories)
# =============================================================================

# -- CMD_INJECTION: command execution primitives --
f sink.system @ sym.imp.system; f sink.popen @ sym.imp.popen; f sink.execve @ sym.imp.execve; f sink.execv @ sym.imp.execv; f sink.execvp @ sym.imp.execvp; f sink.execl @ sym.imp.execl; f sink.execlp @ sym.imp.execlp; f sink.posix_spawn @ sym.imp.posix_spawn

# -- BUFFER_OVERFLOW: unbounded / unchecked write primitives --
f sink.gets @ sym.imp.gets; f sink.strcpy @ sym.imp.strcpy; f sink.strcat @ sym.imp.strcat; f sink.sprintf @ sym.imp.sprintf; f sink.vsprintf @ sym.imp.vsprintf; f sink.stpcpy @ sym.imp.stpcpy; f sink.wcscpy @ sym.imp.wcscpy; f sink.sscanf @ sym.imp.sscanf; f sink.fscanf @ sym.imp.fscanf; f sink.scanf @ sym.imp.scanf; f sink.memcpy @ sym.imp.memcpy; f sink.memmove @ sym.imp.memmove

# -- FORMAT_STRING: printf-family with attacker-reachable format arg --
f sink.printf @ sym.imp.printf; f sink.fprintf @ sym.imp.fprintf; f sink.dprintf @ sym.imp.dprintf; f sink.syslog @ sym.imp.syslog

# -- NETWORK_INPUT: bytes arriving from the network --
f sink.recv @ sym.imp.recv; f sink.recvfrom @ sym.imp.recvfrom; f sink.recvmsg @ sym.imp.recvmsg; f sink.read @ sym.imp.read; f sink.fread @ sym.imp.fread; f sink.SSL_read @ sym.imp.SSL_read; f sink.mbedtls_ssl_read @ sym.imp.mbedtls_ssl_read

# -- FILE_WRITE: arbitrary file write / path traversal primitives --
f sink.fopen @ sym.imp.fopen; f sink.open @ sym.imp.open; f sink.rename @ sym.imp.rename; f sink.symlink @ sym.imp.symlink; f sink.unlink @ sym.imp.unlink; f sink.chmod @ sym.imp.chmod; f sink.chown @ sym.imp.chown; f sink.write @ sym.imp.write

# -- PRIV_ESC: privilege manipulation primitives --
f sink.setuid @ sym.imp.setuid; f sink.setgid @ sym.imp.setgid; f sink.setresuid @ sym.imp.setresuid; f sink.seteuid @ sym.imp.seteuid; f sink.setreuid @ sym.imp.setreuid

?e [elf-sinks] Done. Run: f~sink  or  axt sink.FUNCNAME
