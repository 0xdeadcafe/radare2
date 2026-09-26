#! /usr/bin/env python3
# Copyright (C) 2017 Chase Kanipe
#
# AETHER patch: load the vendored Modality sources from the radare2 corpus
# without depending on the current working directory.  This file is symlinked
# into ~/.local/share/radare2/plugins/plugin.py; the Python modules live in
# ~/.local/share/radare2/modality/.

"""Modality / r2angr plugin entrypoint for radare2."""

import os
import sys

import r2lang
import r2pipe


def _add_modality_paths():
    """Make vendored Modality modules importable in both Docker and host installs."""
    here = os.path.dirname(os.path.abspath(__file__))
    real_here = os.path.dirname(os.path.realpath(__file__))
    candidates = [
        os.environ.get("AETHER_MODALITY_PATH", ""),
        os.path.join(os.path.dirname(here), "modality"),       # loaded via ~/.local/.../plugins/plugin.py symlink
        real_here,                                             # symlink target in .../modality/
        os.path.join(os.path.dirname(real_here), "modality"),
    ]
    for path in candidates:
        if path and os.path.isdir(path) and path not in sys.path:
            sys.path.insert(0, path)


_add_modality_paths()

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

        # Flush stdout — session.run() uses buffered print() internally. Without
        # this flush, M command output may sit in the buffer and never reach r2.
        sys.stdout.flush()

        # Always return integer 1 (handled). Returning a string can make r2lang
        # attempt to execute it as an r2 command and crash on empty/unexpected data.
        return 1

    return {
        "name": "r2-angr",
        "licence": "GPLv3",
        "desc": "Integrates angr with radare2",
        "call": process,
    }


if not r2lang.plugin("core", modality):
    print("An error occurred while registering modality")
