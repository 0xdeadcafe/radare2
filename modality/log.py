"""
log.py -- Shared logging for Modality components.

Single _log helper to avoid duplicating ANSI formatting in every file.
"""

_RESET = "\033[0m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_BLUE = "\033[34m"
_CYAN = "\033[36m"
_MAGENTA = "\033[35m"

COLORS = {
    "yellow": _YELLOW,
    "green": _GREEN,
    "red": _RED,
    "blue": _BLUE,
    "cyan": _CYAN,
    "magenta": _MAGENTA,
}


def colored(text, color):
    """Minimal ANSI coloring -- replaces termcolor dependency."""
    return COLORS.get(color, "") + str(text) + _RESET


def mlog(tag, color, msg):
    """Print a tagged log line: [TAG] message"""
    print(colored("[", "yellow") + colored(tag, color) + colored("] ", "yellow") + str(msg))
