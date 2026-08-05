"""
r2angrdbg.py -- r2 debugger backend for angrdbg (state snapshot from live session).

Provides R2Debugger class implementing angrdbg's Debugger interface,
allowing angr to snapshot register/memory state from an r2 debug session.
"""

import base64
import struct

from angrdbg.abstract_debugger import Debugger, Segment, SEG_PROT_R, SEG_PROT_W, SEG_PROT_X
from angrdbg.context import register_debugger


class R2Debugger(Debugger):
    def __init__(self, r2):
        self.r2 = r2
        self.base_addr = None
        self.got = (0, 0)
        self.plt = (0, 0)
        self.vmmap = []

    def _get_vmmap(self):
        dm = self.r2.cmdj("dmj") or []
        maps = []
        for s in dm:
            start = s["addr"]
            end = s["addr_end"]
            mapperm = 0
            if "r" in s.get("perm", ""):
                mapperm |= SEG_PROT_R
            if "w" in s.get("perm", ""):
                mapperm |= SEG_PROT_W
            if "x" in s.get("perm", ""):
                mapperm |= SEG_PROT_X
            maps.append((start, end, mapperm, s.get("name", "")))
        return maps

    def before_stateshot(self):
        self.vmmap = self._get_vmmap()

        sections = self.r2.cmdj("iSj") or []
        for sec in sections:
            name = sec.get("name", "")
            vaddr = sec.get("vaddr", 0)
            vsize = sec.get("vsize", 0)
            if name in (".got", ".got.plt"):
                self.got = (vaddr, vaddr + vsize)
            elif name == ".plt":
                self.plt = (vaddr, vaddr + vsize)

    def after_stateshot(self, state):
        pass

    def is_active(self):
        return self.r2.cmd("dm").strip() != ""

    def input_file(self):
        path = self.r2.cmdj("ij")['core']['file']
        return open(path, "rb")

    def image_base(self):
        if self.base_addr is None:
            self.base_addr = int(self.r2.cmd("e bin.baddr").strip(), 16)
        return self.base_addr

    # ?? Memory read/write ????????????????????????????????????????????????????

    def _read_mem(self, addr, size):
        """Read raw bytes from target memory via base64."""
        try:
            return base64.b64decode(self.r2.cmd("p6e %d @ %d" % (size, addr)))
        except Exception as e:
            print(f"read_mem({hex(addr)}, {size}) failed: {e}")
            return None

    def get_byte(self, addr):
        data = self._read_mem(addr, 1)
        return data[0] if data else None

    def get_word(self, addr):
        data = self._read_mem(addr, 2)
        return struct.unpack("<H", data)[0] if data else None

    def get_dword(self, addr):
        data = self._read_mem(addr, 4)
        return struct.unpack("<I", data)[0] if data else None

    def get_qword(self, addr):
        data = self._read_mem(addr, 8)
        return struct.unpack("<Q", data)[0] if data else None

    def get_bytes(self, addr, size):
        return self._read_mem(addr, size)

    def put_byte(self, addr, value):
        self.put_bytes(addr, bytes([value]))

    def put_word(self, addr, value):
        self.put_bytes(addr, struct.pack("<H", value))

    def put_dword(self, addr, value):
        self.put_bytes(addr, struct.pack("<I", value))

    def put_qword(self, addr, value):
        self.put_bytes(addr, struct.pack("<Q", value))

    def put_bytes(self, addr, value):
        if isinstance(value, str):
            value = value.encode()
        self.r2.cmd("w6d %s @ %d" % (base64.b64encode(value).decode(), addr))

    # ?? Registers ????????????????????????????????????????????????????????????

    def get_reg(self, name):
        if name == "efl":
            name = "eflags"
        return int(self.r2.cmd("dr?" + name).strip(), 16)

    def set_reg(self, name, value):
        if name == "efl":
            name = "eflags"
        self.r2.cmd("dr %s = %d" % (name, value))

    # ?? Execution control ????????????????????????????????????????????????????

    def step_into(self):
        self.r2.cmd("ds")

    def run(self):
        self.r2.cmd("dc")

    def wait_ready(self):
        pass

    def refresh_memory(self):
        pass

    # ?? Segments ?????????????????????????????????????????????????????????????

    def seg_by_name(self, name):
        for start, end, perms, mname in self.vmmap:
            if name == mname:
                return Segment(name, start, end, perms)
        return None

    def seg_by_addr(self, addr):
        for start, end, perms, name in self.vmmap:
            if int(addr) >= start and int(addr) < end:
                return Segment(name, start, end, perms)
        return None

    def get_got(self):
        return self.got

    def get_plt(self):
        return self.plt

    # ?? Symbol resolution ????????????????????????????????????????????????????

    def resolve_name(self, name):
        """Resolve a symbol name to its address via r2 flags."""
        # Use r2's flag system which is the canonical way to resolve names
        result = self.r2.cmd(f"?v sym.{name}").strip()
        if result and result != "0x0":
            try:
                return int(result, 16)
            except ValueError:
                pass

        # Fallback: search imports
        result = self.r2.cmd(f"?v sym.imp.{name}").strip()
        if result and result != "0x0":
            try:
                return int(result, 16)
            except ValueError:
                pass

        return None


def init(r2):
    """Register the R2Debugger backend with angrdbg."""
    register_debugger(R2Debugger(r2))
