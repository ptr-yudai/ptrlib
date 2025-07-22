from __future__ import annotations
import functools
import getpass
import re
from logging import getLogger
from typing import TYPE_CHECKING, List, Union
if TYPE_CHECKING:
    from ptrlib.connection.unixproc import UnixProcess


logger = getLogger(__name__)

CUSTOM_SUDO_PROMPT = b"[sudo] password: "
GDB_PTRACE_ERROR = b"ptrace: Operation not permitted.\n"
ANSI_RE = re.compile(rb'\x1B\[[0-?]*[ -/]*[@-~]')
CTRL_RE = re.compile(rb'[\x00-\x08\x0B-\x1F]')

def unix_process():
    from ptrlib.connection.unixproc import UnixProcess
    return UnixProcess

def attached(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not hasattr(self, '_gdb'):
            raise RuntimeError("Call `attach` first.")
        return func(self, *args, **kwargs)
    return wrapper

def detached(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if hasattr(self, '_gdb'):
            raise RuntimeError(f"Already attached (pid={self.pid})")
        return func(self, *args, **kwargs)
    return wrapper


class UnixProcessDebugger:
    def __init__(self, pid: int):
        self._pid = pid
        self._gdb_prompt: List[Union[str, bytes]] \
            = [b'(gdb) ', b'gef> ', b'pwndbg> ', b'gdb-peda$ ']

    @property
    @attached
    def gdb(self) -> UnixProcess:
        return self._gdb
    
    @property
    def pid(self) -> int:
        return self._pid

    def _attach_direct(self):
        self._gdb = unix_process()(["gdb", "-q", "-p", str(self._pid)])
        init_msg = self._gdb.recvuntil(self._gdb_prompt, lookahead=True)
        if GDB_PTRACE_ERROR in init_msg:
            raise PermissionError

    def _attach_with_sudo(self):
        self._gdb = unix_process()([
            "sudo", "-S", "-p", CUSTOM_SUDO_PROMPT,
            "gdb", "-q", "-p", str(self._pid)
        ])

        init_msg = self._gdb.recvuntil([b'[sudo] password: '] + self._gdb_prompt, lookahead=True)
        if CUSTOM_SUDO_PROMPT in init_msg:
            # Password is required
            self._gdb.sendlineafter(CUSTOM_SUDO_PROMPT, getpass.getpass())
            init_msg = self._gdb.recvuntil(self._gdb_prompt, lookahead=True)

        if GDB_PTRACE_ERROR in init_msg:
            raise PermissionError

    @detached
    def attach(self) -> 'UnixProcessDebugger':
        """Attach to process with GDB.
        """
        try:
            self._attach_direct()
        except PermissionError:
            self._attach_with_sudo()

        return self

    @attached
    def detach(self):
        """Detach from a process.
        """
        self._gdb.close()
        del self._gdb

    @attached
    def execute(self, command: str) -> str:
        self._gdb.after(self._gdb_prompt).sendline(command)
        # TODO: self._gdb.before(self._gdb_prompt).lastline()
        result = self._gdb.recvuntil(self._gdb_prompt, drop=True, lookahead=True)
        # Remove ANSI escape sequences aggressively
        return CTRL_RE.sub(b'', ANSI_RE.sub(b'', result)).decode().strip()

    def batch_execute(self, commands: List[str]) -> List[str]:
        return [self.execute(command) for command in commands]
    
    @attached
    def interactive(self):
        self._gdb.interactive(prompt='')
        # Return a prompt for further use
        self._gdb.unget(b'(gdb) ')

    def sh(self):
        self.interactive()
