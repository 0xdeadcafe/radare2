"""
debug.py -- Modality debugger: continue, step, explore commands.

Provides: c, cs, cu, cb, co, e, eu, eo commands for symbolic execution control.
"""

from log import colored, mlog


def _log(msg):
    mlog("DEBUG", "blue", msg)


class Debugger():
    def __init__(self, r2angr):
        self.r2angr = r2angr

    def debug_continue(self):
        """c -- Run simulation to completion."""
        _log("Continuing emulation")
        self.r2angr.simgr.run()

    def debug_step(self):
        """cs [n] -- Step n times (default 1)."""
        command = self.r2angr.command
        steps = 1
        if len(command) > 1:
            try:
                steps = int(command[1])
            except ValueError:
                print("Usage: Mcs [step_count]")
                return

        _log(f"Stepping {steps} time(s)")
        for _ in range(steps):
            self.r2angr.simgr.step()

    def debug_continue_until(self):
        """cu <addr|symbol> -- Step until any active state reaches address."""
        command = self.r2angr.command
        if len(command) < 2:
            print("Usage: Mcu <address|symbol>")
            return

        try:
            addr = self._get_addr(command[1])
        except (ValueError, IndexError):
            print(colored(f"{command[1]} not found", "yellow"))
            return

        _log(f"Continuing until {hex(addr)}")
        simgr = self.r2angr.simgr
        while simgr.active and not any(s.addr == addr for s in simgr.active):
            simgr.step()

    def debug_continue_until_branch(self):
        """cb -- Step until the number of active states increases (fork)."""
        _log("Continuing until branch")
        simgr = self.r2angr.simgr
        current = len(simgr.active)
        while len(simgr.active) <= current and len(simgr.active) > 0:
            simgr.step()

    def debug_continue_output(self):
        """co -- Step until stdout changes on any active state."""
        _log("Continuing until stdout changes")
        simgr = self.r2angr.simgr

        if not simgr.active:
            print(colored("No active states", "yellow"))
            return

        # Snapshot by state identity (id) -> output bytes
        initial_output = {id(s): s.posix.dumps(1) for s in simgr.active}

        while simgr.active:
            simgr.step()
            for state in simgr.active:
                sid = id(state)
                prev = initial_output.get(sid)
                current_out = state.posix.dumps(1)
                if prev is None or current_out != prev:
                    try:
                        print(current_out.decode())
                    except UnicodeDecodeError:
                        print(repr(current_out))
                    return

    def debug_explore(self):
        """e -- Explore using CC find/avoid comments."""
        r2p = self.r2angr.r2p
        find = []
        avoid = []

        comments = r2p.cmdj("CCj") or []
        for comment in comments:
            name = comment.get("name", "")
            if name == "find":
                find.append(comment["offset"])
            elif name == "avoid":
                avoid.append(comment["offset"])

        if not find:
            print(colored("Requires at least one 'CC find @ <addr>' comment", "yellow"))
            return

        find_str = ", ".join(colored(hex(a), "green") for a in find)
        avoid_str = ", ".join(colored(hex(a), "red") for a in avoid)
        _log(f"Exploring. Find: [{find_str}]. Avoid: [{avoid_str}].")

        self.r2angr.simgr.explore(find=find, avoid=avoid)

        if self.r2angr.simgr.found:
            _log(colored(f"Found {len(self.r2angr.simgr.found)} solution(s)", "green"))
            self.r2angr.simgr.unstash(from_stash="found", to_stash="active")
        else:
            print(colored("Exploration failed -- no path to find addresses", "red"))

    def debug_explore_until(self):
        """eu <addr|symbol> -- Explore until address is reached."""
        command = self.r2angr.command
        if len(command) < 2:
            print("Usage: Meu <address|symbol>")
            return

        try:
            addr = self._get_addr(command[1])
        except (ValueError, IndexError):
            print(colored(f"{command[1]} not found", "yellow"))
            return

        _log(f"Exploring. Find: [{colored(hex(addr), 'green')}]")
        simgr = self.r2angr.simgr
        simgr.explore(find=addr)

        if simgr.found:
            _log(colored(f"Found {len(simgr.found)} solution(s)", "green"))
            simgr.unstash(from_stash="found", to_stash="active")
        else:
            print(colored("Exploration failed", "red"))

    def debug_explore_output(self):
        """eo <string> -- Explore until string appears in stdout."""
        command = self.r2angr.command
        if len(command) < 2:
            print("Usage: Meo <string>")
            return

        find_string = " ".join(command[1:])
        _log(f"Exploring. Find stdout: [{colored(find_string, 'green')}]")

        simgr = self.r2angr.simgr
        simgr.explore(find=lambda s: find_string.encode() in s.posix.dumps(1))

        if simgr.found:
            _log(colored(f"Found {len(simgr.found)} solution(s)", "green"))
            simgr.unstash(from_stash="found", to_stash="active")
        else:
            print(colored("Exploration failed", "red"))

    # ?? Helpers ??????????????????????????????????????????????????????????????

    def _get_addr(self, s):
        """Resolve address from hex string, int string, or function name."""
        r2p = self.r2angr.r2p
        functions = r2p.cmdj("aflj")
        if functions:
            for f in functions:
                if f["name"] == s:
                    return f["offset"]

        if "0x" in str(s):
            return int(s, 16)
        return int(s)
