#! /usr/bin/env python3
# Copyright (C) 2017 Chase Kanipe
#
# AETHER patch: original used sys.path.append("src/") — a CWD-relative path
# that only works if r2 is launched from the Modality clone directory.
# We resolve src/ relative to this file's own location so it works from any
# working directory, AND we honour PYTHONPATH if the vendor path is already
# on it (preferred in Docker).

"""
modality
"""

import r2lang
import r2pipe
import sys
import os

# Ensure the Modality src/ directory is on sys.path regardless of CWD.
# In Docker this is already set via ENV PYTHONPATH; the insert is a fallback
# for bare-metal installs where PYTHONPATH may not be configured.
_src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

r = r2pipe.open()

session = None
initialized = False

def modality(_):
    global session
    global initialized


    def process(command):
        global session
        global initialized

        if not command.startswith("M"):
            return 0

        binary = r.cmd("i~file").split("\n")[0].split(" ")[-1]

        if not initialized:
            try:
                from r2angr import R2ANGR
                session = R2ANGR(binary, r)
                initialized = True

                session.load_angr()

            except Exception as e:
                print(e)
        try:
            session.run(command[1:])
        except Exception as e:
            print(e)

        # Flush stdout — session.run() uses buffered print() internally.
        # Without this flush, all M command output (help text, state lists,
        # exploration results) sits in the buffer and is never seen by the operator.
        import sys as _sys; _sys.stdout.flush()

        # Always return integer 1 (handled) — returning a string (session.return_value)
        # causes r2lang to attempt to execute it as an r2 command, which triggers
        # a SIGSEGV when the string is empty or unexpected.
        return 1

    return {"name": "r2-angr",
            "licence": "GPLv3",
            "desc": "Integrates angr with radare2",
            "call": process}

if not r2lang.plugin("core", modality):
    print("An error occurred while registering modality")
