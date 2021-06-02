# coding: utf-8
from logging import getLogger
from ptrlib.util.encoding import *
from ptrlib.pwn.tube import *
import ctypes
import os
import time

_is_windows = os.name == 'nt'
if _is_windows:
    import win32api
    import win32con
    import win32file
    import win32pipe
    import win32process
    import win32security

logger = getLogger(__name__)

class WinPipe(object):
    def __init__(self, inherit_handle=True):
        """Create a pipe for Windows

        Create a new pipe

        Args:
            inherit_handle (bool): Whether the child can inherit this handle

        Returns:
            WinPipe: ``WinPipe`` instance.
        """
        attr = win32security.SECURITY_ATTRIBUTES()
        attr.bInheritHandle = inherit_handle
        self.rp, self.wp = win32pipe.CreatePipe(attr, 0)

    @property
    def handle0(self):
        return self.get_handle('recv')
    @property
    def handle1(self):
        return self.get_handle('send')

    def get_handle(self, name='read'):
        """Get endpoint of this pipe

        Args:
            name (str): Handle to get (`recv` or `send`)
        """
        if name in ['read', 'recv', 'stdin']:
            return self.rp

        elif name in ['write', 'send', 'stdout', 'stderr']:
            return self.wp

        else:
            logger.error("You must specify `send` or `recv` as target.")

    @property
    def size(self):
        """Get the number of bytes available to read on this pipe"""
        # (lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage)
        return win32pipe.PeekNamedPipe(self.handle0, 0)[1]

    def _recv(self, size=4096):
        if size <= 0:
            logger.error("`size` must be larger than 0")
            return b''

        buf = ctypes.create_string_buffer(size)
        win32file.ReadFile(self.handle0, buf)

        return buf.raw

    def recv(self, size=4096, timeout=None):
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the pipe.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        start = time.time()
        # Wait until data arrives
        while self.size == 0:
            # Check timeout
            if timeout is not None and time.time() - start > timeout:
                raise TimeoutError("Receive timeout")
            time.sleep(0.01)

        return self._recv(min(self.size, size))

    def send(self, data):
        """Send raw data

        Send raw data through the socket

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        win32file.WriteFile(self.handle1, data)

    def close(self):
        """Cleanly close this pipe"""
        win32api.CloseHandle(self.rp)
        win32api.CloseHandle(self.wp)

    def __del__(self):
        self.close()

class WinProcess(Tube):
    def __init__(self, args, env=None, cwd=None, flags=0, timeout=None):
        """Create a process

        Create a new process and make a pipe.

        Args:
            args (list): The arguments to pass
            env (list) : The environment variables

        Returns:
            Process: ``Process`` instance.
        """
        assert _is_windows
        super().__init__()

        if isinstance(args, list):
            for i, arg in enumerate(args):
                if isinstance(arg, bytes):
                    args[i] = bytes2str(arg)
            self.args = ' '.join(args)
            self.filepath = args[0]

            # Check if arguments are safe for Windows
            for arg in args:
                if '"' not in arg: continue
                if arg[0] == '"' and arg[-1] == '"': continue
                logger.error("You have to escape the arguments by yourself.")
                logger.error("Be noted what you are executing is")
                logger.error("> " + self.args)

        else:
            self.args = args

        # Create pipe
        self.stdin = WinPipe()
        self.stdout = WinPipe()
        self.default_timeout = timeout
        self.timeout = timeout

        # Create process
        info = win32process.STARTUPINFO()
        info.dwFlags = win32con.STARTF_USESTDHANDLES
        info.hStdInput = self.stdin.handle0
        info.hStdOutput = self.stdout.handle1
        info.hStdError = self.stdout.handle1
        # (hProcess, hThread, dwProcessId, dwThreadId)
        self.proc, _, self.pid, _ = win32process.CreateProcess(
            None, self.args, # lpApplicationName, lpCommandLine
            None, None,      # lpProcessAttributes, lpThreadAttributes
            True, flags,     # bInheritHandles, dwCreationFlags
            env, cwd,        # lpEnvironment, lpCurrentDirectory
            info             # lpStartupInfo
        )

        logger.info("Successfully created new process (PID={})".format(self.pid))

    def _settimeout(self, timeout):
        """Set timeout value"""
        if timeout is None:
            self.timeout = self.default_timeout
        elif timeout > 0:
            self.timeout = timeout

    def _socket(self):
        return self.proc

    def _recv(self, size, timeout=None):
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the pipe.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        if size <= 0:
            logger.error("`size` must be larger than 0")
            return b''

        buf = self.stdout.recv(size, self.timeout)
        return buf

    def close(self):
        if self.proc:
            win32api.CloseHandle(self.proc)
            self.proc = None
            logger.info("Process killed (PID={0})".format(self.pid))

    def send(self, data):
        """Send raw data

        Send raw data through the socket

        Args:
            data (bytes) : Data to send
        """
        self.stdin.send(data)

    def shutdown(self, target):
        """Close a connection

        Args:
            target (str): Pipe to close (`recv` or `send`)
        """
        if target in ['write', 'send', 'stdin']:
            self.stdin.close()

        elif target in ['read', 'recv', 'stdout', 'stderr']:
            self.stdout.close()

        else:
            logger.error("You must specify `send` or `recv` as target.")

    def __del__(self):
        self.close()
