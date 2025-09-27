from __future__ import annotations
import functools
import getpass
import os
import re
import signal
import sys
from logging import getLogger
from typing import TYPE_CHECKING, List, Union, overload
if TYPE_CHECKING:
    from ptrlib.connection.unixproc import UnixProcess


logger = getLogger(__name__)

CUSTOM_SUDO_PROMPT = "[sudo] password: "
GDB_ATTACH_MSG = b"Attaching to process "
GDB_PTRACE_ERROR = b"ptrace: "
ANSI_RE = re.compile(rb'\x1B\[[0-?]*[ -/]*[@-~]')
CTRL_RE = re.compile(rb'[\x00-\x08\x0B-\x1F]')

def unix_process():
    """Returns a UnixProcess class
    """
    from ptrlib.connection.unixproc import UnixProcess
    return UnixProcess

def attached(func):
    """Assert the debugger is already attached
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.is_attached:
            raise RuntimeError("Call `attach` first.")
        return func(self, *args, **kwargs)
    return wrapper

def detached(func):
    """Assert the debugger is not attached
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.is_attached:
            raise RuntimeError(f"Already attached (pid={self.pid})")
        return func(self, *args, **kwargs)
    return wrapper


class UnixProcessDebugger:
    """Debugger for Unix processes
    """
    def __init__(self, pid: int):
        self._pid = pid
        self._gdb = None
        self._gdb_prompt: List[Union[str, bytes]] \
            = [b'(gdb) ', b'gef> ', b'pwndbg> ', b'gdb-peda$ ']

    @property
    @attached
    def gdb(self) -> UnixProcess:
        """Debugger session
        """
        if self._gdb is None:
            raise RuntimeError("Debugger is not attached.")
        return self._gdb

    @property
    def is_attached(self) -> bool:
        """Check if the debugger is attached to a process.
        """
        return self._gdb is not None

    @property
    def debug(self) -> str:
        """Debug mode
        """
        return self.gdb.debug

    @debug.setter
    def debug(self, mode: bool):
        self.gdb.debug = mode

    @property
    def pid(self) -> int:
        """PID of the target process
        """
        return self._pid

    def _attach_direct(self):
        self._gdb = unix_process()(["gdb", "-q", "-p", str(self._pid)])
        self._gdb.recvuntil(GDB_ATTACH_MSG)
        init_msg = self._gdb.recvuntil(self._gdb_prompt, consume=False)
        if GDB_PTRACE_ERROR in init_msg:
            raise PermissionError(f"Cannot attach pid={self._pid}")

    def _attach_with_sudo(self):
        self._gdb = unix_process()([
            "sudo", "-S", "-p", CUSTOM_SUDO_PROMPT,
            "gdb", "-q", "-p", str(self._pid)
        ], use_tty=True)

        init_msg = b''
        for _ in range(3):
            init_msg = self._gdb.recvuntil([CUSTOM_SUDO_PROMPT] + self._gdb_prompt, consume=False)
            if CUSTOM_SUDO_PROMPT.encode() in init_msg:
                # Password is required (The user does not set NOPASSWD in sudoers)
                self._gdb.sendlineafter(CUSTOM_SUDO_PROMPT, getpass.getpass(CUSTOM_SUDO_PROMPT))
            else:
                break

        if GDB_PTRACE_ERROR in init_msg:
            raise PermissionError(f"Cannot attach pid={self._pid}")

    @detached
    def attach(self) -> 'UnixProcessDebugger':
        """Attach to process with GDB.

        Return:
            UnixProcessDebugger: This debugger instance.
        """
        # TODO: Check if target process has already been attached
        # TODO: Check if we have root privilege
        try:
            self._attach_direct()
            return self
        except PermissionError:
            # Fallback to sudo if failed to attach
            pass

        self._attach_with_sudo()
        return self

    @attached
    def detach(self):
        """Detach from a process.
        """
        self.gdb.close()
        del self._gdb

    @overload
    def execute(self, command: str, resume: bool=False) -> str: ...
    @overload
    def execute(self, command: List[str], resume: bool=False) -> List[str]: ...
    @attached
    def execute(self,
                command: Union[str, List[str]],
                resume: bool=False) -> Union[str, List[str]]:
        """Execute a GDB command.

        Args:
            command (str): A command to execute, or a list of commands.
            resume (bool): If true, continue execution after all commands are done.

        Returns:
            str: Result of the command.

        Examples:
            ```
            conn = sock.process.attach()
            stdout = int(conn.execute("p/x &_IO_2_1_stdout_").split(' = ')[1], 16)
            conn.execute("break puts", resume=True)
            sock.sendline(b"Hello")
            res = conn.execute([
                f"set {{long}}{stdout} = 0xfbad1887",
                f"x/4xg {stdout}"
            ])
            print(res[1])
            ```
        """
        if isinstance(command, list):
            result = [self.execute(c) for c in command]
            if resume:
                self.execute('continue')
            return result

        self.gdb.after(self._gdb_prompt).sendline(command)
        result = self.gdb.recvuntil(self._gdb_prompt, drop=True, consume=False)
        # Remove ANSI escape sequences aggressively
        result = CTRL_RE.sub(b'', ANSI_RE.sub(b'', result)).decode().strip()
        if resume:
            self.gdb.after(self._gdb_prompt).sendline("continue")
        return result

    @attached
    def interactive(self):
        """Interact with GDB terminal
        """
        def _continue_process():
            self.gdb.unget(b'(gdb) ')

        def _send_signal() -> bool:
            os.kill(self.gdb.pid, signal.SIGINT)
            return True

        def _handle_special_command() -> str:
            cmd = sys.stdin.readline()
            if cmd == '':
                # Ctrl+D
                raise KeyboardInterrupt("Continuing.")

            if cmd.strip() in ['q', 'quit', 'exit']:
                raise KeyboardInterrupt("Continuing.")

            return cmd

        self.gdb.interactive(prompt='',
                             readline=_handle_special_command,
                             oninterrupt=_send_signal,
                             onexit=_continue_process)

    def sh(self):
        """Interact with GDB terminal
        """
        self.interactive()

__all__ = ['UnixProcessDebugger']
