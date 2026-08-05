#!/usr/bin/python3
"""
r2angr.py -- Modality core: angr symbolic execution inside radare2.

Usage: loaded as r2 core plugin via r2pm. All commands prefixed with M.
       Type M? inside r2 for help.
"""

from debug import Debugger
from stash import Stash
from hooks import Hooks
from watcher import Watcher
from initializer import Initializer
from bitvectors import Bitvectors
from exploit import Exploiter
from precompute import Precompute
from log import colored, mlog

import os
import sys

import claripy


class R2ANGR():

    def __init__(self, binary, r2p):
        self.is_initialized = False
        self.command = ""
        self.return_value = ""

        # Instance-level components
        self.debugger = Debugger(self)
        self.stash = Stash(self)
        self.watcher = Watcher(self)
        self.hooks = Hooks(self)
        self.initializer = Initializer(self)
        self.bitvectors = Bitvectors(self)
        self.exploiter = Exploiter(self)
        self.precompute = Precompute(self)

        # Symbolic stdin -- size tunable via env
        _stdin_bytes = int(os.environ.get("R2ANGR_STDIN_SIZE", "1024"))
        self.stdin = claripy.BVS("stdin", _stdin_bytes * 8)
        self.binary = binary
        self.r2p = r2p

        self.commands = [
            ("c",     self.debugger.debug_continue,              "c",     "Continue emulation"),
            ("cs",    self.debugger.debug_step,                  "cs [n]", "Continue one (or n) steps"),
            ("cu",    self.debugger.debug_continue_until,        "cu <addr>", "Continue until address"),
            ("cb",    self.debugger.debug_continue_until_branch, "cb",    "Continue until branch"),
            ("co",    self.debugger.debug_continue_output,       "co",    "Continue until stdout changes"),

            ("e",     self.debugger.debug_explore,               "e",     "Explore using find/avoid comments"),
            ("eu",    self.debugger.debug_explore_until,         "eu <addr>", "Explore until address"),
            ("eo",    self.debugger.debug_explore_output,        "eo <string>", "Explore until string in stdout"),

            ("ie",    self.initializer.initialize_entry,         "ie",    "Initialize at entry point"),
            ("ib",    self.initializer.initialize_blank,         "ib",    "Initialize blank state at current address"),
            ("id",    self.initializer.initialize_debugger,      "id",    "Initialize from debugger state"),

            ("sl",    self.stash.list,                           "sl",    "List states"),
            ("slv",   self.stash.info,                           "slv",   "List active states verbose"),
            ("si",    self.stash.print_input,                    "si",    "Print state stdin"),
            ("so",    self.stash.print_output,                   "so",    "Print state stdout"),
            ("sk",    self.stash.kill,                           "sk <index|addr>", "Kill state"),
            ("ska",   self.stash.kill_all,                       "ska",   "Kill all states"),
            ("sr",    self.stash.revive,                         "sr <index|addr>", "Revive state"),
            ("sra",   self.stash.revive_all,                     "sra",   "Revive all states"),
            ("se",    self.stash.extract,                        "se <index|addr>", "Extract single state, kill others"),

            ("br",    self.bitvectors.symbolize_register,        "br <reg>", "Symbolize register"),
            ("bs",    self.bitvectors.solve,                     "bs",    "Solve all bitvector values"),

            ("hf",    self.hooks.hook_functions,                 "hf",    "Hook all functions"),
            ("hl",    self.hooks.hook_loops,                     "hl",    "Hook all loops"),

            ("w",     self.watcher.add_watchpoint,               "w <addr> [msg]", "Add watchpoint"),
            ("wl",    self.watcher.list_watchpoints,             "wl",    "List watchpoints"),
            ("wr",    self.watcher.remove_watchpoint,            "wr <addr>", "Remove watchpoint"),

            ("E",     self.exploiter.explore,                    "E",     "Explore until unconstrained PC (overflow)"),
            ("Ep",    self.exploiter.build_ret2plt,              "Ep",    "Build ret2plt payload from crash state"),

            ("pre",   self.precompute.pre_compute,              "pre [json]", "Full pre-compute: CFG + sinks + reach + CRC"),
            ("sinks", self.precompute.find_sinks,               "sinks", "Find dangerous sink callers via CFG"),
            ("reach", self.precompute.compute_reach,            "reach", "Reachability from entry to sinks"),
            ("gate",  self.precompute.find_gates,               "gate",  "Detect CRC gates, solve with Z3"),
        ]

    def load_angr(self):
        mlog("R2ANGR", "green", "Importing angr")
        import angr
        self.angr = angr
        mlog("R2ANGR", "green", "Loading r2angr")

        # Detect CloudShield ELF (e_machine=0xC0) -- Cisco IOS MIPS32-BE
        # angr can't map EM_CLOUDSHIELD to an arch; override explicitly.
        import archinfo, subprocess
        _main_opts = {}
        try:
            with open(self.binary, 'rb') as _f:
                _ehdr = _f.read(20)
            _is_elf = _ehdr[:4] == b'\x7fELF'
            _e_machine = (_ehdr[18] << 8) | _ehdr[19] if _is_elf else 0
            if _e_machine == 0xC0:  # EM_CLOUDSHIELD -- Cisco IOS MIPS32-BE
                _main_opts = {
                    'arch': archinfo.ArchMIPS32(endness=archinfo.Endness.BE),
                    'base_addr': 0,
                }
            elif not _is_elf:
                # Flat/raw binary -- get base addr from r2 and detect arch
                try:
                    _r2_arch  = self.r2p.cmd('e asm.arch').strip()
                    _r2_bits  = int(self.r2p.cmd('e asm.bits').strip() or '32')
                    _r2_be    = self.r2p.cmd('e cfg.bigendian').strip().lower() == 'true'
                    _r2_base  = int(self.r2p.cmd('o~[2]').split()[0].strip(), 16)
                except Exception:
                    _r2_arch = 'mips'; _r2_bits = 32; _r2_be = True; _r2_base = 0x80000000
                import archinfo as _ai
                if _r2_arch == 'mips' and _r2_bits == 32:
                    _arch = _ai.ArchMIPS32(endness=_ai.Endness.BE if _r2_be else _ai.Endness.LE)
                elif _r2_arch == 'arm' and _r2_bits == 32:
                    _arch = _ai.ArchARM(endness=_ai.Endness.BE if _r2_be else _ai.Endness.LE)
                elif _r2_arch == 'arm' and _r2_bits == 64:
                    _arch = _ai.ArchAArch64()
                else:
                    _arch = _r2_arch
                _main_opts = {
                    'backend':    'blob',
                    'arch':       _arch,
                    'base_addr':  _r2_base,
                    'entry_point': _r2_base,
                }
                mlog('R2ANGR', 'yellow', f'flat binary: blob loader, arch={_r2_arch}, base={_r2_base:#x}')
        except Exception:
            pass
        self.project = angr.Project(self.binary, auto_load_libs=False,
                                    main_opts=_main_opts if _main_opts else None)

        self._init_entry_state()
        self.is_initialized = True

    def _init_entry_state(self):
        state = self.project.factory.entry_state(stdin=self.stdin)
        self.simgr = self.project.factory.simgr(state, save_unconstrained=True)
        mlog("R2ANGR", "green", "Initialized at entry point")

    def run(self, command):
        command = command.split(" ")
        self.command = command

        if "?" in command[0]:
            self.help(command)
            return

        found = False
        for c, f, usage, desc in self.commands:
            if c == command[0]:
                if not self.is_initialized:
                    print("r2angr not initialized -- use Mi command to load angr")
                else:
                    self.return_value = ""
                    f()
                    self.update_highlight()
                found = True
                break

        if not found:
            self.help(command)

    def help(self, command):
        self.return_value = ""
        prefix = command[0].replace("?", "")
        for c, f, usage, desc in self.commands:
            if not prefix or c.startswith(prefix):
                print(f"| M{colored(usage, 'yellow'):30s} {colored(desc, 'green')}")

    def update_highlight(self):
        # Clear old r2angr comments
        for comment in self.r2p.cmdj("CCj") or []:
            if "r2angr" in comment.get("name", ""):
                self.r2p.cmd("CC- @ " + hex(comment["offset"]))
                self.r2p.cmd("ecH- @ " + hex(comment["offset"]))

        # Mark deadended states red
        for i, state in enumerate(self.simgr.deadended):
            self.r2p.cmd("ecHi red @ " + hex(state.addr))
            self.r2p.cmd('CC+r2angr "deadended" state ' + str(i) + " @ " + hex(state.addr))

        # Mark active states blue
        for i, state in enumerate(self.simgr.active):
            self.r2p.cmd("ecHi blue @ " + hex(state.addr))
            self.r2p.cmd('CC+r2angr "active" state ' + str(i) + " @ " + hex(state.addr))
            if "invalid" not in self.r2p.cmd("pd 2 @ " + hex(state.addr)):
                self.r2p.cmd("s " + hex(state.addr))

        # Mark watchpoints magenta
        for addr, (count, name) in self.watcher.watchpoints.items():
            self.r2p.cmd("ecHi magenta @ " + hex(addr))
            label = f"Watchpoint {name} (Hits: {count})" if count > 0 else f"Watchpoint {name}"
            self.r2p.cmd("CC+" + label + " @ " + hex(addr))
