from logging import getLogger
from typing import List, Mapping, Optional, Union
import os
import subprocess
from ptrlib.binary.encoding import bytes2str
from .tube import Tube

_is_windows = os.name == 'nt'
if _is_windows:
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32file
    import win32pipe
    import win32process
    import win32security

logger = getLogger(__name__)

class WinPipe(object):
    def __init__(self,
                 read: Optional[bool]=False,
                 write: Optional[bool]=False,
                 size: Optional[int]=65536):
        """Create a pipe for Windows

        Create a new pipe with overlapped I/O.

        Args:
            read: True if read mode
            write: True if write mode
            size: Default buffer size for this pipe
            timeout: Default timeout in second
        """
        if read and write:
            mode = win32pipe.PIPE_ACCESS_DUPLEX
            self._access = win32con.GENERIC_READ | win32con.GENERIC_WRITE
        elif write:
            mode = win32pipe.PIPE_ACCESS_OUTBOUND
            self._access = win32con.GENERIC_READ
        else:
            mode = win32pipe.PIPE_ACCESS_INBOUND
            self._access = win32con.GENERIC_WRITE

        self._attr = win32security.SECURITY_ATTRIBUTES()
        self._attr.bInheritHandle = True

        self._name = f"\\\\.\\pipe\\ptrlib.{os.getpid()}.{os.urandom(8).hex()}"
        self._handle = win32pipe.CreateNamedPipe(
            self._name, mode | win32file.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
            1, size, size, 0, self._attr
        )
        assert self._handle != win32file.INVALID_HANDLE_VALUE, \
            "Could not create a pipe"

    @property
    def name(self) -> str:
        return self._name
    
    @property
    def access(self) -> int:
        return self._access
    
    @property
    def attributes(self) -> any:
        return self._attr

    @property
    def handle(self) -> int:
        return self._handle

    def close(self):
        """Gracefully close this pipe
        """
        win32api.CloseHandle(self._handle)

    def __del__(self):
        self.close()

class WinProcess(Tube):
    #
    # Constructor
    #
    def __init__(self,
                 args: Union[List[Union[str, bytes]], str],
                 env: Optional[Union[Mapping[bytes, Union[bytes, str]], Mapping[str, Union[bytes, str]]]]=None,
                 cwd: Optional[Union[bytes, str]]=None,
                 flags: int = 0,
                 raw: bool=False,
                 stdin : Optional[WinPipe]=None,
                 stdout: Optional[WinPipe]=None,
                 stderr: Optional[WinPipe]=None,
                 **kwargs):
        """Create a Windows process

        Create a Windows process and make a pipe.

        Args:
            args   : The arguments to pass
            env    : The environment variables
            cwd    : Working directory
            flags  : dwCreationFlags passed to CreateProcess
            raw    : Disable pty if this parameter is true
            stdin  : File descriptor of standard input
            stdout : File descriptor of standard output
            stderr : File descriptor of standard error

        Returns:
            WinProcess: ``WinProcess`` instance

        Examples:
            ```
            p = Process("cmd.exe", cwd="C:\\")
            p = Process(["cmd", "dir"],
                        stderr=subprocess.DEVNULL)
            p = Process("more C:\\test.txt", env={"X": "123"})
            ```
        """
        assert _is_windows, "WinProcess cannot work on Unix"
        assert isinstance(args, (str, bytes, list)), \
            "`args` must be either str, bytes, or list"
        assert env is None or isinstance(env, dict), \
            "`env` must be a dictionary"
        assert cwd is None or isinstance(cwd, (str, bytes)), \
            "`cwd` must be either str or bytes"

        self._current_timeout = 0
        super().__init__(**kwargs)

        if isinstance(args, list):
            for i, arg in enumerate(args):
                if isinstance(arg, bytes):
                    args[i] = bytes2str(arg)
            args = subprocess.list2cmdline(args)

        else:
            args = bytes2str(args)

        self._filepath = args

        # Prepare stdio
        if stdin is None:
            self._stdin  = WinPipe(write=True)
        proc_stdin = win32file.CreateFile(
            self._stdin.name, self._stdin.access,
            0, self._stdin.attributes,
            win32con.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, None
        )

        if stdout is None:
            self._stdout = WinPipe(read=True)
        proc_stdout = win32file.CreateFile(
            self._stdout.name, self._stdout.access,
            0, self._stdout.attributes,
            win32con.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, None
        )
        
        if stderr is None:
            self._stderr = self._stdout
            proc_stderr = proc_stdout
        else:
            proc_stderr = win32file.CreateFile(
                self._stderr.name, self._stderr.access,
                0, self._stderr.attributes,
                win32con.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, None
            )

        # Open process
        info = win32process.STARTUPINFO()
        info.dwFlags = win32con.STARTF_USESTDHANDLES
        info.hStdInput  = proc_stdin
        info.hStdOutput = proc_stdout
        info.hStdError  = proc_stderr
        self._proc, _, self._pid, _ = win32process.CreateProcess(
            None, args, None, None, True, flags, env, cwd, info
        )

        win32file.CloseHandle(proc_stdin)
        win32file.CloseHandle(proc_stdout)
        if proc_stdout != proc_stderr:
            win32file.CloseHandle(proc_stderr)

        # Wait until connection
        win32pipe.ConnectNamedPipe(self._stdin.handle)
        win32pipe.ConnectNamedPipe(self._stdout.handle)
        win32pipe.ConnectNamedPipe(self._stderr.handle)

        self._returncode = None

        logger.info(f"Successfully created new process {str(self)}")

    #
    # Property
    #
    @property
    def returncode(self) -> Optional[int]:
        return self._returncode

    @property
    def pid(self) -> int:
        return self._pid

    #
    # Implementation of Tube
    #
    def _settimeout_impl(self, timeout: Union[int, float]):
        """Set timeout

        Args:
            timeout: Timeout in second (Maximum precision is millisecond)
        """
        self._current_timeout = timeout

    def _recv_impl(self, size: int) -> bytes:
        """Receive raw data

        Args:
            size: Size to receive

        Returns:
            bytes: Received data
        """
        if self._current_timeout == 0:
            # Without timeout
            try:
                _, data = win32file.ReadFile(self._stdout.handle, size)
                return data
            except Exception as err:
                raise err from None

        else:
            # With timeout
            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)
            try:
                _, data = win32file.ReadFile(self._stdout.handle, size, overlapped)
                state = win32event.WaitForSingleObject(
                    overlapped.hEvent, int(self._current_timeout * 1000)
                )
                if state == win32event.WAIT_OBJECT_0:
                    result = win32file.GetOverlappedResult(self._stdout.handle, overlapped, True)
                    if isinstance(result, int):
                        # NOTE: GetOverlappedResult does not return data
                        #       when overlapped ReadFile is successful.
                        #       We need to use the result of this API because 
                        #       we cannot access the number of bytes read by ReadFile.
                        #       See https://github.com/mhammond/pywin32/issues/430
                        return data[:result]
                    else:
                        return result[1]
                else:
                    raise TimeoutError("Timeout (_recv_impl)", b'')
            finally:
                win32file.CloseHandle(overlapped.hEvent)

    def _send_impl(self, data: bytes) -> int:
        """Send raw data

        Args:
            data: Data to send

        Returns:
            int: The number of bytes written
        """
        _, n = win32file.WriteFile(self._stdin.handle, data)
        return n
    
    def _close_impl(self):
        win32api.TerminateProcess(self._proc, 0)
        win32api.CloseHandle(self._proc)
        logger.info(f"Process killed {str(self)}")

    def _is_alive_impl(self) -> bool:
        """Check if process is alive

        Returns:
            bool: True if process is alive, otherwise False
        """
        status = win32process.GetExitCodeProcess(self._proc)
        if status == win32con.STILL_ACTIVE:
            return True
        else:
            self._returncode = status
            return False
    
    def _shutdown_recv_impl(self):
        """Kill receiver connection
        """
        self._stdout.close()
    
    def _shutdown_send_impl(self):
        """Kill sender connection
        """
        self._stdin.close()

    def __str__(self) -> str:
        return f'{self._filepath} (PID={self._pid})'
