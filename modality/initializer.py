"""
initializer.py -- State initialization commands.

Commands: ie (entry), ib (blank at seek), id (from debugger)
"""

from log import colored, mlog


def _log(msg):
    mlog("R2ANGR", "green", msg)


class Initializer():
    def __init__(self, r2angr):
        self.r2angr = r2angr

    def initialize_entry(self):
        """ie -- Initialize angr state at binary entry point."""
        state = self.r2angr.project.factory.entry_state(stdin=self.r2angr.stdin)
        self.r2angr.simgr = self.r2angr.project.factory.simgr(state, save_unconstrained=True)
        _log("Initialized at entry point")

    def initialize_blank(self):
        """ib -- Initialize blank angr state at r2's current seek address."""
        addr_str = self.r2angr.r2p.cmd("s").strip()
        addr = int(addr_str, 16)

        state = self.r2angr.project.factory.blank_state(
            addr=addr, stdin=self.r2angr.stdin
        )

        # MIPS: blank states need $gp pointing at .got for PIC relative loads
        arch_name = self.r2angr.project.arch.name.lower()
        if "mips" in arch_name:
            got = self.r2angr.project.loader.main_object.sections_map.get(".got")
            if got:
                state.regs.gp = got.vaddr

        self.r2angr.simgr = self.r2angr.project.factory.simgr(state, save_unconstrained=True)
        _log(f"Initialized blank state at {hex(addr)}")

    def initialize_debugger(self):
        """id -- Create angr state from current r2 debugger state."""
        try:
            import r2angrdbg
        except ImportError:
            print(colored("r2angrdbg not available -- install angrdbg package", "red"))
            return

        r2angrdbg.init(self.r2angr.r2p)

        try:
            from angrdbg.context import StateManager
            state = StateManager().get_state()
        except Exception as e:
            print(colored(f"Failed to get debugger state: {e}", "red"))
            return

        state.options.add(self.r2angr.angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        self.r2angr.simgr = self.r2angr.project.factory.simgr(state, save_unconstrained=True)
        _log("Initialized from debugger state")
