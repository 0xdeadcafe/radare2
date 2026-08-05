"""
watcher.py -- Symbolic execution watchpoints.

Commands: w <addr> [msg], wl, wr <addr>
"""

from log import colored


class Watcher():
    def __init__(self, r2angr):
        self.r2angr = r2angr
        self.watchpoints = {}

    def add_watchpoint(self):
        """w <addr> [message] -- Add a watchpoint hook at address."""
        command = self.r2angr.command
        if len(command) < 2:
            print("Usage: Mw <hex_addr> [message]")
            return

        addr = int(command[1], 16)
        message = " ".join(command[2:]) if len(command) > 2 else ""

        self.watchpoints[addr] = (0, message)
        self.r2angr.project.hook(addr, self._hook_watchpoint, length=0)
        print(f"Added watchpoint at {hex(addr)}" + (f": {message}" if message else ""))

    def list_watchpoints(self):
        """wl -- List all watchpoints."""
        if not self.watchpoints:
            print(colored("No watchpoints set", "yellow"))
            return

        print(colored("Watchpoints:", "magenta"))
        for i, (addr, (count, message)) in enumerate(self.watchpoints.items()):
            label = message if message else hex(addr)
            print(f"  {i} {hex(addr):20s} hits={count}  {label}")

    def remove_watchpoint(self):
        """wr <addr> -- Remove watchpoint at address."""
        command = self.r2angr.command
        if len(command) < 2:
            print("Usage: Mwr <hex_addr>")
            return

        addr = int(command[1], 16)
        if addr in self.watchpoints:
            del self.watchpoints[addr]
            self.r2angr.project.unhook(addr)
            print(f"Removed watchpoint at {hex(addr)}")
        else:
            print(colored(f"No watchpoint at {hex(addr)}", "yellow"))

    def _hook_watchpoint(self, state):
        """Callback fired when execution hits a watchpoint address."""
        addr = state.solver.eval(state.regs._ip)
        if addr not in self.watchpoints:
            return

        count, message = self.watchpoints[addr]
        self.watchpoints[addr] = (count + 1, message)

        simgr = self.r2angr.simgr
        status = colored(f"[{len(simgr.active)}|", "yellow") + colored(str(len(simgr.deadended)), "red") + colored("]", "yellow")
        hits = colored(f"{{Hits: {count + 1}}}", "cyan")
        label = message if message else f"watchpoint at {hex(addr)}"

        print(f" {status} {hits} {label}")
