"""
bitvectors.py -- Symbolize registers and solve constraints.

Commands: br <reg>, bs
"""

import claripy
from log import colored


class Bitvectors():
    def __init__(self, r2angr):
        self.r2angr = r2angr
        self.symbolic_values = []

    def symbolize_register(self):
        """br <reg> -- Make a register symbolic across all active states."""
        if len(self.r2angr.command) < 2:
            print("Usage: Mbr <register_name>")
            return

        reg = self.r2angr.command[1]
        arch = self.r2angr.project.arch

        # Determine register size from archinfo
        reg_info = arch.registers.get(reg)
        if reg_info is None:
            print(colored(f"Register '{reg}' not found in arch {arch.name}", "red"))
            return

        reg_size_bits = reg_info[1] * 8  # archinfo stores (offset, size_bytes)

        for i, state in enumerate(self.r2angr.simgr.active):
            bvs = claripy.BVS(f"sym_{reg}_{len(self.symbolic_values)}", reg_size_bits)
            setattr(state.regs, reg, bvs)
            self.symbolic_values.append(bvs)
            print(f"Symbolized {reg} ({reg_size_bits}bit) in "
                  + colored("active", "cyan") + f" state {i} at "
                  + colored(hex(state.addr), "green"))

    def solve(self):
        """bs -- Solve all symbolic values in active states."""
        if not self.symbolic_values:
            print(colored("No symbolic values to solve", "yellow"))
            return

        for i, state in enumerate(self.r2angr.simgr.active):
            print(colored(f"State {i} @ {hex(state.addr)}:", "cyan"))
            for bv in self.symbolic_values:
                try:
                    solution = state.solver.eval(bv)
                    print(f"  {bv.args[0]}: {solution} ({hex(solution)})")
                except Exception as e:
                    print(f"  {bv.args[0]}: unsolvable ({e})")
