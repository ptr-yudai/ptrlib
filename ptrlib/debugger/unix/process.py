import ctypes
import ctypes.util
import functools
import os
import re
from logging import getLogger
from typing import Callable, Dict, Generator, NamedTuple, List, Optional, Union
from ptrlib.binary.encoding import str2bytes
from ptrlib.types import GeneratorOrInt
from .debug import UnixProcessDebugger

logger = getLogger(__name__)

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.strerror.argtypes = [ctypes.c_int]
_libc.strerror.restype = ctypes.c_char_p
_libc.process_vm_readv.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_ulong,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_libc.process_vm_readv.restype = ctypes.c_ssize_t
_libc.process_vm_writev.argtypes = _libc.process_vm_readv.argtypes
_libc.process_vm_writev.restype = ctypes.c_ssize_t

def require_procfs(func):
    """Decorator that captures FileNotFoundError and shows error message
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except FileNotFoundError:
            logger.error("pid=%d is dead or procfs is disabled.", self._pid)
            raise
    return wrapper


class UnixMemoryRegion(NamedTuple):
    """A class that represents a range of memory
    """
    start: int
    end: int
    perm: str
    offset: int
    path: str

    def __repr__(self):
        return f"UnixMemoryRegion('{str(self)}')"

    def __str__(self):
        return f"0x{self.start:016x}-0x{self.end:016x} {self.perm} {self.path}"

class UnixProcessManager:
    """Unix process manager
    """
    def __init__(self, pid: int):
        """
        Args:
            pid (int): Process ID to attach
        """
        # TODO: Ask for sudo
        self._pid = pid

    @property
    def pid(self) -> int:
        return self._pid

    @property
    @require_procfs
    def cmdline(self) -> List[bytes]:
        """Get command line arguments
        """
        with open(f"/proc/{self._pid}/cmdline", "rb") as f:
            return f.read().rstrip(b'\x00').split(b'\x00')

    @property
    @require_procfs
    def environ(self) -> List[bytes]:
        """Get environment variables
        """
        with open(f"/proc/{self._pid}/environ", "rb") as f:
            return [
                env
                for env in f.read().rstrip(b'\x00').split(b'\x00')
                if b'=' in env
            ]

    @property
    @require_procfs
    def files(self) -> Dict[int, Optional[str]]:
        """Get open files
        """
        fds = {}
        for fd in os.listdir(f'/proc/{self._pid}/fd'):
            try:
                fds[int(fd)] = os.readlink(f'/proc/{self._pid}/fd/{fd}')
            except OSError:
                fds[int(fd)] = None
        return fds

    @property
    @require_procfs
    def threads(self) -> List[int]:
        """Get list of thread ids
        """
        return [int(t) for t in os.listdir(f'/proc/{self._pid}/task') if t.isdigit()]

    @property
    @require_procfs
    def children(self) -> List['UnixProcessManager']:
        """Get list of child processes
        """
        children = []
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue

            try:
                stat = open(f'/proc/{pid}/stat', 'rb').read()
            except (OSError, IOError):
                continue

            idx = stat.rfind(b')')
            if idx == -1:
                continue

            rest = stat[idx+1:].strip().split()
            if len(rest) < 2:
                continue

            ppid = int(rest[4])
            if ppid == self.pid:
                children.append(UnixProcessManager(int(pid)))

        return children

    @property
    def vmmap(self) -> List[UnixMemoryRegion]:
        """Get a list of memory map of this process.
        """
        maps = []
        with open(f'/proc/{self._pid}/maps', 'r') as f:
            for line in f:
                m = re.match(r"^([0-9a-f]+)-([0-9a-f]+) ([-rwxsp]+) ([0-9a-f]+) \S+ \d+\s+(.*)", line)
                if m is None: # Unreachable
                    continue

                start = int(m.groups()[0], 16)
                end = int(m.groups()[1], 16)
                perm = m.groups()[2]
                offset = int(m.groups()[3], 16)
                path = m.groups()[4]
                maps.append(UnixMemoryRegion(start, end, perm, offset, path))

        return maps

    def attach(self, pid: Optional[Union[int, Callable[['UnixProcessManager'], int]]]=None) -> UnixProcessDebugger:
        """Attach to a process with given pid.

        Args:
            pid (int): Process ID or a function or lambda that returns a pid.

        Examples:
            ```
            sock = Process("/bin/cat")
            conn = sock.process.attach()
            #conn.debug = True

            conn.execute("break write", resume=True)
            sock.sendline(b"Hello, World!")

            a, b = conn.execute(["p/x $rsi", "x/1s $rsi"])
            print(a)  # $1 = 0x7d0f5d1de000
            print(b)  # 0x7d0f5d1de000: "Hello, World!\\n"

            conn.detach()
            ```
        """
        if pid is None:
            pid = self.pid
        elif callable(pid):
            pid = pid(self)

        return UnixProcessDebugger(pid).attach()

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

    def write(self, addr: int, data: Union[str, bytes]) -> int:
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

    def _search_internal(self,
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
            if start is None and end is not None:
                start = end - length
            elif start is not None and end is None:
                end = start + length
            else:
                raise ValueError("`len` is specified but neither `start` nor `end` is set")

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
            if mem.start >= 0x8000_0000_0000: # Skip non-canonical and kernel memory
                # TODO: Support 32-bit
                continue
            if mem.path == '[vvar]': # NOTE: Heuristic skip
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

    def search(self,
               data: Union[str, bytes],
               start: Optional[int]=None,
               end: Optional[int]=None,
               length: Optional[int]=None) -> GeneratorOrInt:
        """Search for memory

        Args:
            data (bytes): Data to search
            start (int): Lower bound for search
            end (int): Upper bound for search
            len (int): Length of region to search (Requires either `start` or `end`)

        Returns:
            generator: A generator to yield matching addresses
        """
        return GeneratorOrInt(
            self._search_internal(data, start, end, length),
            str2bytes(data)
        )

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

        n_read = _libc.process_vm_readv(
            self._pid, local_iov, 1, remote_iov, 1, 0
        )
        if n_read == -1:
            e = ctypes.get_errno()
            s = _libc.strerror(e).decode()
            raise OSError(e, f"process_vm_readv failed: {s}")

        return buf.raw

    def process_vm_write(self, addr: int, data: Union[str, bytes]) -> int:
        """Write memory with using process_vm_writev

        Args:
            addr (int): Remote address to write data to
            data (bytes): Data to write

        Returns:
            int: Number of bytes written to the memory
        """
        if isinstance(data, str):
            data = str2bytes(data)

        buf = ctypes.create_string_buffer(data)
        local_iov  = (ctypes.c_void_p * 2)(ctypes.addressof(buf), len(data))
        remote_iov = (ctypes.c_void_p * 2)(addr, len(data))

        n_written = _libc.process_vm_writev(
            self._pid, local_iov, 1, remote_iov, 1, 0
        )
        if n_written == -1:
            e = ctypes.get_errno()
            s = _libc.strerror(e).decode()
            raise OSError(e, f"process_vm_writev failed: {s}")

        return n_written

    def __repr__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return f'<pid={self.pid}>'


__all__ = ['UnixProcessManager', 'UnixMemoryRegion']
