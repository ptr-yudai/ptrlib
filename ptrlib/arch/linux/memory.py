import ctypes
import ctypes.util
import re
from logging import getLogger
from typing import Generator, NamedTuple, List, Optional, Union
from ptrlib.binary.encoding import str2bytes

logger = getLogger(__name__)


class LinuxMemoryRegion(NamedTuple):
    start: int
    end: int
    perm: str
    offset: int
    path: Optional[str]

    def __repr__(self):
        return f"LinuxMemoryRegion('{str(self)}')"

    def __str__(self):
        return f"0x{self.start:016x}-0x{self.end:016x} {self.perm} {self.path}"

class LinuxProcessMemory(object):
    """Memory inspector for Linux
    """
    def __init__(self, pid: int, sudo: bool=True):
        """
        Args:
            pid (int): Process ID to attach
            sudo (bool): If this parameter is set to true and a permission error occurs, ask pkexec prompt to get root privilege (Default is true)
        """
        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self._pid = pid

        self._libc.strerror.argtypes = [ctypes.c_int]
        self._libc.strerror.restype = ctypes.c_char_p

        self._libc.process_vm_readv.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        self._libc.process_vm_readv.restype = ctypes.c_ssize_t

        self._libc.process_vm_writev.argtypes = self._libc.process_vm_readv.argtypes
        self._libc.process_vm_writev.resype = ctypes.c_ssize_t

    @property
    def vmmap(self) -> List[LinuxMemoryRegion]:
        maps = []
        with open(f"/proc/{self._pid}/maps", "r") as f:
            for line in f:
                m = re.match(r"^([0-9a-f]+)-([0-9a-f]+) ([-rwxsp]+) ([0-9a-f]+) \S+ \d+\s+(.*)", line)
                start = int(m.groups()[0], 16)
                end = int(m.groups()[1], 16)
                perm = m.groups()[2]
                offset = int(m.groups()[3], 16)
                path = m.groups()[4]
                maps.append(LinuxMemoryRegion(start, end, perm, offset, path))
        return maps

    def read(self, addr: int, size: int) -> bytes:
        """Attempt to read memory

        Args:
            addr (int): Remote address to read data from
            size (int): Size to read

        Returns:
            bytes: Data read from the memory
        """
        e1 = e2 = None

        # 1. /proc/pid/mem is the most reliable
        try:
            return self.proc_mem_read(addr, size)
        except OSError as e:
            e2 = e

        # 2. process_vm_readv can bypass anti-debug
        try:
            return self.process_vm_read(addr, size)
        except OSError as e:
            e1 = e

        # 3. TODO: ptrace
        raise e1 or e2

    def write(self, addr: int, data: bytes) -> int:
        """Attempt to write memory

        Args:
            addr (int): Remote address to write data to
            data (bytes): Data to write

        Returns:
            int: Number of bytes written to the memory
        """
        e1 = e2 = None

        # 1. /proc/pid/mem is the most reliable
        try:
            return self.proc_mem_write(addr, data)
        except OSError as e:
            e2 = e

        # 2. process_vm_writev can bypass anti-debug
        try:
            return self.process_vm_write(addr, data)
        except OSError as e:
            e1 = e

        # 3. TODO: ptrace
        raise e1 or e2

    def search(self,
               data: Union[str, bytes],
               start: Optional[int]=None,
               end: Optional[int]=None,
               length: Optional[int]=None) -> Generator[int, None, None]:
        """Search for memory

        Args:
            data (bytes): Data to search
            start (int): Lower bound for search
            end (int): Upper bound for search
            len (int): Length of region to search (Requires either `start` or `end`)

        Returns:
            generator: A generator to yield matching addresses
        """
        if isinstance(data, str):
            data = str2bytes(data)

        if length is not None:
            if (start or end) is None:
                raise ValueError("`len` is specified but neither `start` nor `end` is set")
            elif start is None:
                start = end - length
            else:
                end = start + length
        
        if start is None:
            start = 0
        if end is None:
            end = 1 << 64 # Works fine both for 32-bit and 64-bit

        prev_end = -1
        region_start = 0
        offset = 0
        haystack = b''
        for mem in self.vmmap:
            if mem.end <= start or mem.start > end:
                continue
            elif mem.start >= 0x8000_0000_0000: # Skip non-canonical and kernel memory
                continue
            elif mem.path == '[vvar]': # NOTE: Heuristic skip
                continue

            if mem.start != prev_end:
                region_start = mem.start
                offset = 0
                haystack = b''
            prev_end = mem.end

            # Search page by page
            for addr in range(mem.start, mem.end, 0x1000):
                try:
                    haystack += self.read(addr, 0x1000)
                except OSError as e:
                    logger.warning(f"Could not read memory ({addr}, {addr+0x1000}): {e}")
                    continue

            # TODO: Implement stream KMP
            while True:
                found = haystack.find(data, offset)
                if found == -1: break
                yield region_start + found
                offset = found + 1

            if offset <= len(haystack) - len(data):
                offset = len(haystack) - len(data) + 1

    def proc_mem_read(self, addr: int, size: int):
        """Read memory with using /proc/pid/mem

        Args:
            addr (int): Remote address to read data from
            size (int): Size to read

        Returns:
            bytes: Data read from the memory
        """
        with open(f"/proc/{self._pid}/mem", "rb") as f:
            f.seek(addr, 0)
            return f.read(size)

    def proc_mem_write(self, addr: int, data: Union[str, bytes]) -> int:
        """Write memory with using process_vm_writev

        Args:
            addr (int): Remote address to write data to
            data (bytes): Data to write

        Returns:
            int: Number of bytes written to the memory
        """
        if isinstance(data, str):
            data = str2bytes(data)

        with open(f"/proc/{self._pid}/mem", "wb") as f:
            f.seek(addr, 0)
            return f.write(data)

    def process_vm_read(self, addr: int, size: int) -> bytes:
        """Read memory with using process_vm_readv

        Args:
            addr (int): Remote address to read data from
            size (int): Size to read

        Returns:
            bytes: Data read from the memory
        """
        buf = ctypes.create_string_buffer(size)
        local_iov  = (ctypes.c_void_p * 2)(ctypes.addressof(buf), size)
        remote_iov = (ctypes.c_void_p * 2)(addr, size)

        n_read = self._libc.process_vm_readv(
            self._pid, local_iov, 1, remote_iov, 1, 0
        )
        if n_read == -1:
            e = ctypes.get_errno()
            s = self._libc.strerror(e).decode()
            raise OSError(e, f"process_vm_readv failed: {s}")

        return buf.raw

    def process_vm_write(self, addr: int, data: bytes) -> int:
        """Write memory with using process_vm_writev

        Args:
            addr (int): Remote address to write data to
            data (bytes): Data to write

        Returns:
            int: Number of bytes written to the memory
        """
        buf = ctypes.create_string_buffer(data)
        local_iov  = (ctypes.c_void_p * 2)(ctypes.addressof(buf), len(data))
        remote_iov = (ctypes.c_void_p * 2)(addr, len(data))

        n_written = self._libc.process_vm_writev(
            self._pid, local_iov, 1, remote_iov, 1, 0
        )
        if n_written == -1:
            e = ctypes.get_errno()
            s = self._libc.strerror(e).decode()
            raise OSError(e, f"process_vm_writev failed: {s}")

        return n_written
    
