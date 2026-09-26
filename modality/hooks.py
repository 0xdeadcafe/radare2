"""
hooks.py -- Modality function and loop hooking.

Commands: hf, hl
"""

from log import colored, mlog


def _log(msg):
    mlog("HOOKS", "magenta", msg)


class Hooks():
    def __init__(self, r2angr):
        self.r2angr = r2angr
        self.loops_visited = {}

    def hook_functions(self):
        """hf -- Hook all named functions for tracing (non-destructive, length=0)."""
        functions = self.r2angr.r2p.cmdj("aflj") or []
        for func in functions:
            name = func.get("name", "")
            addr = func["offset"]
            # length=0 means the hook fires but does NOT replace any instructions
            self.r2angr.project.hook(addr, self._trace_hook, length=0)
            _log("Hooking: " + colored(name, "green") + f" at {hex(addr)}")

    def hook_loops(self):
        """hl -- Hook all loop entry points for tracking iteration counts."""
        proj = self.r2angr.project

        cfg_fast = proj.analyses.CFGFast()
        functions = [cfg_fast.functions[a] for a in cfg_fast.functions]
        loops = proj.analyses.LoopFinder(functions=functions).loops

        _log(f"Found {len(loops)} loops")

        for loop in loops:
            addr = loop.entry.addr
            proj.hook(addr, self._loop_hook, length=0)
            self.loops_visited[addr] = 0

    # ?? Hook callbacks ???????????????????????????????????????????????????????

    def _trace_hook(self, state):
        name = self._resolve_name(state.addr)
        _log(colored(f"Called {name}", "green"))

    def _loop_hook(self, state):
        addr = state.addr
        count = self.loops_visited.get(addr, 0)
        simgr = self.r2angr.simgr

        status = colored(f" [{len(simgr.active)}|", "yellow") + colored(str(len(simgr.deadended)), "red") + colored("]", "yellow")

        if count == 0:
            _log(colored(f"Starting loop at {hex(addr)}", "yellow"))
        else:
            _log(status + colored(f" {{Loop count: {count}}}", "cyan") + f" Looping at {hex(addr)}")

        self.loops_visited[addr] = count + 1

    # ?? Helpers ??????????????????????????????????????????????????????????????

    def _resolve_name(self, addr):
        """Look up function name by address."""
        functions = self.r2angr.r2p.cmdj("aflj") or []
        for func in functions:
            if func["offset"] == addr:
                return func.get("signature", func.get("name", hex(addr)))
        return hex(addr)
