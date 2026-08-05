"""
stash.py -- State management: list, kill, revive, extract, print I/O.

Commands: sl, slv, si, so, sk, ska, sr, sra, se
"""

from log import colored


class Stash():
    def __init__(self, r2angr):
        self.r2angr = r2angr

    def info(self):
        """slv -- Verbose listing of active states with disassembly."""
        for i, state in enumerate(self.r2angr.simgr.active):
            self._print(colored("Active", "cyan") + f" state {i} at " + colored(hex(state.addr), "green"))
            disasm = self.r2angr.r2p.cmd("pdi 5 @ " + hex(state.addr))
            for line in disasm.split("\n"):
                self._print("   " + line)

    def list(self):
        """sl -- List all active and deadended states."""
        simgr = self.r2angr.simgr

        if simgr.active:
            self._print(colored("Active", "cyan") + " states:")
            for i, state in enumerate(simgr.active):
                self._print(f"  {i} " + colored(hex(state.addr), "yellow"))
            self._print("")

        if simgr.deadended:
            self._print(colored("Deadended", "red") + " states:")
            for i, state in enumerate(simgr.deadended):
                self._print(f"  {i} " + colored(hex(state.addr), "yellow"))
            self._print("")

        if not simgr.active and not simgr.deadended:
            self._print(colored("No states", "yellow"))

    def print_input(self):
        """si [index] -- Print stdin of active states."""
        command = self.r2angr.command
        simgr = self.r2angr.simgr

        if len(command) > 1:
            try:
                idx = int(command[1])
                self._print_bytes(simgr.active[idx].posix.dumps(0))
            except (ValueError, IndexError) as e:
                print(colored(f"Error: {e}", "red"))
        else:
            for i, state in enumerate(simgr.active):
                print(colored("Active", "cyan") + f" state {i} at " + colored(hex(state.addr), "green") + ":")
                self._print_bytes(state.posix.dumps(0))

    def print_output(self):
        """so [index] -- Print stdout of active states."""
        command = self.r2angr.command
        simgr = self.r2angr.simgr

        if len(command) > 1:
            try:
                idx = int(command[1])
                self._print_bytes(simgr.active[idx].posix.dumps(1))
            except (ValueError, IndexError) as e:
                print(colored(f"Error: {e}", "red"))
        else:
            for i, state in enumerate(simgr.active):
                self._print(colored("Active", "cyan") + f" state {i} at " + colored(hex(state.addr), "green") + ":")
                self._print_bytes(state.posix.dumps(1))

    def kill(self):
        """sk <index|0xaddr> -- Move state from active to deadended."""
        command = self.r2angr.command
        simgr = self.r2angr.simgr

        if len(command) < 2:
            print("Usage: Msk <index|0xaddr>")
            return

        addr = self._resolve_addr(command[1], simgr.active)
        if addr is None:
            return
        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == addr)

    def kill_all(self):
        """ska -- Kill all active states."""
        self.r2angr.simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: True)

    def revive(self):
        """sr <index|0xaddr> -- Move state from deadended to active."""
        command = self.r2angr.command
        simgr = self.r2angr.simgr

        if len(command) < 2:
            print("Usage: Msr <index|0xaddr>")
            return

        addr = self._resolve_addr(command[1], simgr.deadended)
        if addr is None:
            return
        simgr.move(from_stash='deadended', to_stash='active', filter_func=lambda s: s.addr == addr)

    def revive_all(self):
        """sra -- Revive all deadended states."""
        self.r2angr.simgr.move(from_stash='deadended', to_stash='active', filter_func=lambda s: True)

    def extract(self):
        """se <index|0xaddr> -- Keep one state, kill all others."""
        command = self.r2angr.command
        simgr = self.r2angr.simgr

        if len(command) < 2:
            print("Usage: Mse <index|0xaddr>")
            return

        addr = self._resolve_addr(command[1], simgr.active)
        if addr is None:
            return
        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr != addr)

    # ?? Helpers ??????????????????????????????????????????????????????????????

    def _resolve_addr(self, arg, stash):
        """Resolve index or hex address from a stash list."""
        if "0x" in arg:
            return int(arg, 16)
        try:
            idx = int(arg)
            return stash[idx].addr
        except (ValueError, IndexError):
            print(colored(f"Invalid state reference: {arg}", "red"))
            return None

    def _print_bytes(self, data):
        try:
            self._print(data.decode())
        except UnicodeDecodeError:
            self._print(repr(data))

    def _print(self, s):
        self.r2angr.return_value += s + "\n"
        print(s)
