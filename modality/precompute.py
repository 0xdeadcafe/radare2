"""
precompute.py -- Modality pre-computation: Mpre, Mreach, Mgate, Msinks.

Commands added to the Modality M table:
  Mpre [json_path]    Full pre-computation: build CFG, find sinks, compute
                      reachability, detect and solve CRC gates.
  Msinks              Find all callers of dangerous imports via CFG.
  Mreach              Compute reachability from network entry to sink callers.
  Mgate               Detect CRC gates on path, solve with Z3.
"""

import json
import os
import time
from collections import deque
from log import colored, mlog


DANGEROUS_SINKS = [
    "system", "popen", "execve", "execl", "execvp",
    "strcpy", "strcat", "gets", "scanf", "vscanf",
    "sprintf", "vsprintf",
    "memcpy", "memmove",
]

NETWORK_ENTRIES = [
    "recv", "recvfrom", "recvmsg", "read", "fread",
    "accept", "fgets",
]


def _log(msg):
    mlog("Mpre", "cyan", msg)


def _warn(msg):
    mlog("Mpre", "red", "WARN: " + str(msg))


class Precompute():
    def __init__(self, r2angr):
        self.r2angr = r2angr

    # ?? Internal helpers ?????????????????????????????????????????????????????

    def _get_plt(self):
        """Get PLT mapping from r2's import table."""
        try:
            imports = self.r2angr.r2p.cmdj("iij") or []
            plt = {}
            for imp in imports:
                name = imp.get("name", "")
                addr = imp.get("plt") or imp.get("vaddr")
                if name and addr:
                    plt[name] = addr
            return plt
        except Exception as e:
            _warn(f"iij failed: {e}")
            return {}

    def _get_cache(self):
        """Get or create the precompute cache dict."""
        if not hasattr(self.r2angr, "_precompute"):
            self.r2angr._precompute = {}
        return self.r2angr._precompute

    def _build_cfg(self):
        """Build or return cached CFGFast."""
        cache = self._get_cache()

        if "cfg" not in cache:
            _log("building CFGFast ...")
            t0 = time.time()
            try:
                cfg = self.r2angr.project.analyses.CFGFast(
                    resolve_indirect_jumps=True,
                    normalize=True,
                )
                _log(f"CFGFast done in {time.time()-t0:.1f}s -- {len(cfg.functions)} functions")
                cache["cfg"] = cfg
            except Exception as e:
                _warn(f"CFGFast failed: {e}")
                cache["cfg"] = None
        return cache["cfg"]

    def _find_sink_callers_cfg(self, cfg, plt):
        """Use CFG to find functions that call dangerous sinks."""
        results = {}
        for sink in DANGEROUS_SINKS:
            sink_addr = plt.get(sink)
            if not sink_addr:
                continue
            node = cfg.get_any_node(sink_addr)
            if not node:
                continue
            callers = set()
            for pred in cfg.graph.predecessors(node):
                func = cfg.functions.floor_func(pred.addr)
                if func:
                    callers.add(func.addr)
            if callers:
                results[sink] = sorted(callers)
        return results

    def _find_entry_function(self, cfg, plt):
        """Find the network entry function (first caller of recv/read/accept)."""
        for fn_name in NETWORK_ENTRIES:
            addr = plt.get(fn_name)
            if not addr:
                continue
            node = cfg.get_any_node(addr)
            if not node:
                continue
            for pred in cfg.graph.predecessors(node):
                func = cfg.functions.floor_func(pred.addr)
                if func:
                    _log(f"network entry: {func.name} @ {hex(func.addr)} (via {fn_name})")
                    return func.addr, func.name
        return None, None

    def _bfs_reachable(self, cfg, start_addr):
        """BFS over callgraph to find all functions reachable from start."""
        reachable = set()
        queue = deque([start_addr])
        while queue:
            addr = queue.popleft()
            if addr in reachable:
                continue
            reachable.add(addr)
            for callee in cfg.functions.callgraph.successors(addr):
                if callee not in reachable:
                    queue.append(callee)
        return reachable

    def _find_gates_on_path(self, cfg, entry_addr):
        """Find gate-like functions reachable from entry via BFS."""
        gates = []
        visited = set()
        queue = deque([entry_addr])
        while queue:
            a = queue.popleft()
            if a in visited:
                continue
            visited.add(a)
            fn = cfg.functions.get(a)
            if fn and self._looks_like_gate(fn):
                gates.append(fn)
            if fn:
                for callee in cfg.functions.callgraph.successors(a):
                    if callee not in visited:
                        queue.append(callee)
        return gates

    def _looks_like_gate(self, func):
        """Heuristic: does this function look like a CRC/checksum gate?"""
        name = func.name.lower()
        if any(k in name for k in ["crc", "checksum", "chksum", "cksum", "hash",
                                     "verify", "check", "valid"]):
            return True
        try:
            blocks = list(func.blocks)
            if 3 <= len(blocks) <= 30 and len(list(func.endpoints)) == 2:
                return True
        except Exception:
            pass
        return False

    def _solve_gate(self, gate_func_addr, stdin_size=64):
        """
        Use angr + Z3 to find concrete input bytes that make gate return
        non-zero (pass). Creates a fresh project to avoid polluting state.
        """
        import claripy

        # Fresh project so we don't pollute the main one's knowledge base
        _pc_opts = self.r2angr.project.loader.main_object.options if hasattr(self.r2angr, 'project') else {}
        _pc_main = {'arch': self.r2angr.project.arch, 'base_addr': 0} if hasattr(self.r2angr, 'project') else {}
        proj = self.r2angr.angr.Project(self.r2angr.binary, auto_load_libs=False,
                                        main_opts=_pc_main if _pc_main else None)
        arch = proj.arch.name.lower()

        try:
            sym = claripy.BVS("gate_input", stdin_size * 8)
            buf = 0x1000000
            state = proj.factory.call_state(
                gate_func_addr, buf, stdin_size,
                add_options={"ZERO_FILL_UNCONSTRAINED_REGISTERS"},
            )
            state.memory.store(buf, sym)
            simgr = proj.factory.simgr(state)
            simgr.run(until=lambda sm: len(sm.active) == 0, n=1000)

            ret_reg = (
                "v0"  if "mips" in arch else
                "r0"  if "arm"  in arch else
                "rax"
            )
            for dead in simgr.deadended:
                rv = getattr(dead.regs, ret_reg)
                if dead.solver.satisfiable(extra_constraints=[rv != 0]):
                    concrete = dead.solver.eval(sym, cast_to=bytes)
                    return "SOLVED", concrete.hex()
            return "UNSOLVED", None
        except Exception as e:
            return "ERROR", str(e)[:120]

    # ?? M commands ????????????????????????????????????????????????????????????

    def pre_compute(self):
        """
        Mpre [json_path] -- Full pre-computation pipeline:
          1. Build CFGFast
          2. Find dangerous sink callers
          3. Find network entry function
          4. Compute reachability
          5. Detect CRC gates, attempt Z3 solving
          6. Output JSON report
        """
        cmd = self.r2angr.command
        out_path = cmd[1] if len(cmd) > 1 else f"/tmp/Mpre_{os.getpid()}.json"

        t_total = time.time()
        _log("starting pre-computation ...")

        cfg = self._build_cfg()
        if cfg is None:
            _warn("CFGFast failed -- aborting Mpre")
            return

        plt          = self._get_plt()
        sink_callers = self._find_sink_callers_cfg(cfg, plt)
        entry_addr, entry_name = self._find_entry_function(cfg, plt)

        # Reachability
        reachable = self._bfs_reachable(cfg, entry_addr) if entry_addr else set()
        reachable_sinks = {}
        for sink, callers in sink_callers.items():
            rc = [hex(a) for a in callers if a in reachable]
            if rc:
                reachable_sinks[sink] = rc

        # CRC gate detection + solving
        gates = []
        if entry_addr:
            gate_funcs = self._find_gates_on_path(cfg, entry_addr)
            for fn in gate_funcs:
                _log(f"solving gate {fn.name} @ {hex(fn.addr)} ...")
                status, result = self._solve_gate(fn.addr)
                gates.append({
                    "addr": hex(fn.addr),
                    "name": fn.name,
                    "status": status,
                    "solved_bytes": result,
                })
                _log(f"  -> {status}" + (f": {result[:16]}..." if result else ""))

        # Build find addresses for exploration
        find_addrs = []
        for sink in DANGEROUS_SINKS:
            if sink in reachable_sinks:
                for caller_hex in reachable_sinks[sink]:
                    find_addrs.append({"addr": caller_hex, "reason": f"{sink}() caller"})

        output = {
            "generated_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "binary":        self.r2angr.binary,
            "analysis_time_s": round(time.time() - t_total, 1),
            "cfg_functions": len(cfg.functions),
            "network_entry": {
                "addr": hex(entry_addr) if entry_addr else None,
                "name": entry_name,
            },
            "plt_sinks_present": {s: hex(plt[s]) for s in DANGEROUS_SINKS if s in plt},
            "sink_callers":  {s: [hex(a) for a in c] for s, c in sink_callers.items()},
            "reachable_sinks": reachable_sinks,
            "crc_gates":     gates,
            "modality_config": {
                "entry_addr":  hex(entry_addr) if entry_addr else None,
                "find_addrs":  find_addrs[:20],
                "crc_gates_solved": [g for g in gates if g["status"] == "SOLVED"],
            },
        }

        # Cache for use by other M commands
        cache = self._get_cache()
        cache.update({
            "cfg": cfg,
            "plt": plt,
            "sink_callers": sink_callers,
            "reachable_sinks": reachable_sinks,
            "entry_addr": entry_addr,
            "gates": gates,
        })

        with open(out_path, "w") as f:
            json.dump(output, f, indent=2)

        # Human-readable summary
        print()
        _log(f"pre-computation complete in {output['analysis_time_s']}s")
        _log(f"binary:  {self.r2angr.binary}")
        _log(f"entry:   {entry_name} @ {hex(entry_addr) if entry_addr else 'not found'}")
        _log(f"sinks reachable: {list(reachable_sinks.keys())}")
        _log(f"CRC gates: {len(gates)} detected, "
             f"{sum(1 for g in gates if g['status']=='SOLVED')} solved")
        _log(f"output:  {out_path}")
        _log("next:    s <entry_addr> -> Mib -> Me -> Msi")
        print()

        self.r2angr.return_value = out_path

    def find_sinks(self):
        """Msinks -- Find all callers of dangerous imports via CFG."""
        cfg = self._build_cfg()
        if cfg is None:
            return

        plt          = self._get_plt()
        sink_callers = self._find_sink_callers_cfg(cfg, plt)

        if not sink_callers:
            _log("no dangerous sink callers found via CFG")
            return

        print()
        for sink in DANGEROUS_SINKS:
            if sink not in sink_callers:
                continue
            callers = sink_callers[sink]
            print(colored(f"  {sink}() -- {len(callers)} caller(s):", "yellow"))
            for addr in callers[:10]:
                fn = cfg.functions.get(addr)
                name = fn.name if fn else f"fcn.{hex(addr)}"
                print(f"    {hex(addr):20s}  {name}")
            if len(callers) > 10:
                print(f"    ... and {len(callers)-10} more")
        print()

    def compute_reach(self):
        """Mreach -- Compute reachability from network entry to sink callers."""
        cfg = self._build_cfg()
        if cfg is None:
            return

        plt = self._get_plt()
        sink_callers = self._find_sink_callers_cfg(cfg, plt)
        entry_addr, entry_name = self._find_entry_function(cfg, plt)

        if not entry_addr:
            _warn("no network entry found")
            return

        reachable = self._bfs_reachable(cfg, entry_addr)
        _log(f"{len(reachable)} functions reachable from {entry_name} @ {hex(entry_addr)}")
        print()

        for sink in DANGEROUS_SINKS:
            if sink not in sink_callers:
                continue
            callers = sink_callers[sink]
            r  = [a for a in callers if a in reachable]
            nr = [a for a in callers if a not in reachable]
            if r:
                print(colored(f"  v REACHABLE  {sink}()", "green"))
                for a in r:
                    fn = cfg.functions.get(a)
                    print(f"      {hex(a):20s}  {fn.name if fn else 'unknown'}"
                          + colored("  ? target for Mib", "cyan"))
            if nr:
                print(colored(f"  X unreachable {sink}()", "red") +
                      f" ({len(nr)} caller(s) -- skip these)")
        print()

    def find_gates(self):
        """Mgate -- Detect CRC gates on path from entry, solve with Z3."""
        cfg = self._build_cfg()
        if cfg is None:
            return

        plt = self._get_plt()
        entry_addr, entry_name = self._find_entry_function(cfg, plt)
        if not entry_addr:
            _warn("no network entry found -- cannot detect gates without entry point")
            return

        gates = self._find_gates_on_path(cfg, entry_addr)

        if not gates:
            _log("no CRC/checksum gate functions detected on path from entry")
            return

        _log(f"detected {len(gates)} potential gate(s) -- attempting Z3 solving ...")
        print()

        for fn in gates:
            status, result = self._solve_gate(fn.addr)
            if status == "SOLVED":
                print(colored(f"  v SOLVED  {fn.name} @ {hex(fn.addr)}", "green"))
                print(f"    gate_input hex: {result}")
                print(colored("    embed these bytes in PoC header before Mib/Me", "cyan"))
            elif status == "UNSOLVED":
                print(colored(f"  X UNSOLVED  {fn.name} @ {hex(fn.addr)}", "yellow"))
                print( "    Z3 could not find satisfying input -- hook this function:")
                print(colored(f"    r2_cmd(sid, \"CC avoid @ {hex(fn.addr)}\")", "cyan"))
            else:
                print(colored(f"  ? ERROR  {fn.name} @ {hex(fn.addr)}: {result}", "red"))
        print()
