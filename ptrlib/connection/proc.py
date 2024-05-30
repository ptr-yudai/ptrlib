import os
import select
import subprocess
from logging import getLogger
from typing import List, Mapping, Optional, Union
from ptrlib.arch.linux.sig import signal_name
from ptrlib.binary.encoding import bytes2str
from .tube import Tube, tube_is_open
from .winproc import WinProcess


_is_windows = os.name == 'nt'
if not _is_windows:
    import fcntl
    import pty
    import tty

logger = getLogger(__name__)

class UnixProcess(Tube):
    #
    # Constructor
    #
    def __init__(self,
                 args: Union[bytes, str, List[Union[bytes, str]]],
                 env: Optional[Union[Mapping[bytes, Union[bytes, str]], Mapping[str, Union[bytes, str]]]]=None,
                 cwd: Optional[Union[bytes, str]]=None,
                 shell: Optional[bool]=None,
                 raw: bool=False,
                 stdin : Optional[int]=None,
                 stdout: Optional[int]=None,
                 stderr: Optional[int]=None,
                 **kwargs):
        """Create a UNIX process

        Create a UNIX process and make a pipe.

        Args:
            args   : The arguments to pass
            env    : The environment variables
            cwd    : Working directory
            shell  : If true, `args` is a shell command
            raw    : Disable pty if this parameter is true
            stdin  : File descriptor of standard input
            stdout : File descriptor of standard output
            stderr : File descriptor of standard error

        Returns:
            Process: ``Process`` instance

        Examples:
            ```
            p = Process("/bin/ls", cwd="/tmp")
            p = Process(["wget", "www.example.com"],
                        stderr=subprocess.DEVNULL)
            p = Process("cat /proc/self/maps", env={"LD_PRELOAD": "a.so"})
            ```
        """
        assert not _is_windows, "UnixProcess cannot work on Windows"
        assert isinstance(args, (str, bytes, list)), \
            "`args` must be either str, bytes, or list"
        assert env is None or isinstance(env, dict), \
            "`env` must be a dictionary"
        assert cwd is None or isinstance(cwd, (str, bytes)), \
            "`cwd` must be either str or bytes"

        # NOTE: We need to initialize _current_timeout before super constructor
        #       because it may call _settimeout_impl
        self._current_timeout = 0
        super().__init__(**kwargs)

        # Guess shell mode based on args
        if shell is None:
            if isinstance(args, (str, bytes)):
                args = [bytes2str(args)]
                if ' ' in args[0]:
                    shell = True
                    logger.info("Detected whitespace in arguments: " \
                                "`shell=True` enabled")
                else:
                    shell = False
            else:
                shell = False

        else:
            if isinstance(args, (str, bytes)):
                args = [bytes2str(args)]
            else:
                args = list(map(bytes2str, args))

        # Prepare stdio
        master = self._slave = None
        if not raw:
            master, self._slave = pty.openpty()
            tty.setraw(master)
            tty.setraw(self._slave)
            stdout = self._slave

        if stdin  is None: stdin  = subprocess.PIPE
        if stdout is None: stdout = subprocess.PIPE
        if stderr is None: stderr = subprocess.STDOUT

        # Open process
        assert isinstance(shell, bool), "`shell` must be boolean"
        try:
            self._proc = subprocess.Popen(
                args, cwd=cwd, env=env,
                shell=shell,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
            )
        except FileNotFoundError as err:
            logger.error(f"Could not execute {args[0]}")
            raise err from None

        self._filepath = args[0]

        self._returncode = None

        # Duplicate master
        if master is not None:
            self._proc.stdout = os.fdopen(os.dup(master), 'r+b', 0)
            os.close(master)

        # Set in non-blocking mode
        fd = self._proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        logger.info(f"Successfully created new process {str(self)}")
        self._init_done = True

    #
    # Properties
    #
    @property
    def returncode(self) -> Optional[int]:
        return self._returncode
    
    @property
    def pid(self) -> int:
        return self._proc.pid

    #
    # Implementation of Tube methods
    #
    def _settimeout_impl(self, timeout: Union[int, float]):
        self._current_timeout = timeout

    def _recv_impl(self, size: int) -> bytes:
        """Receive raw data

        Receive raw data of maximum `size` bytes through the pipe.

        Args:
            size: Data size to receive

        Returns:
            bytes: The received data
        """
        if self._current_timeout == 0:
            timeout = None
        else:
            timeout = self._current_timeout

        if timeout is not None:
            ready, [], [] = select.select(
                [self._proc.stdout.fileno()], [], [], timeout
            )
            if len(ready) == 0:
                raise TimeoutError("Timeout (_recv_impl)", b'') from None

        else:
            while self.is_alive():
                ready, [], [] = select.select(
                    [self._proc.stdout.fileno()], [], [], self._POLL_TIMEOUT
                )
                if ready: break

        try:
            data = self._proc.stdout.read(size)
        except subprocess.TimeoutExpired:
            raise TimeoutError("Timeout (_recv_impl)", b'') from None

        if data is None:
            raise ConnectionAbortedError("Connection closed (_recv_impl)", b'') from None

        return data

    def _send_impl(self, data: bytes) -> int:
        """Send raw data

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error
        """
        try:
            n_written = self._proc.stdin.write(data)
            self._proc.stdin.flush()
            return n_written
        except IOError as err:
            logger.error(f"Broken pipe: {str(self)}")
            raise err from None

    def _shutdown_recv_impl(self):
        """Close stdin
        """
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        if self._proc.stderr is not None:
            self._proc.stderr.close()

    def _shutdown_send_impl(self):
        """Close stdout
        """
        self._proc.stdin.close()

    def _close_impl(self):
        """Close process
        """
        if self._is_alive_impl():
            self._proc.kill()
            self._proc.wait()
            logger.info(f"{str(self)} killed by `close`")

        if self._slave is not None: # PTY mode
            os.close(self._slave)
            self._slave = None

        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
        except BrokenPipeError:
            pass

        try:
            if self._proc.stdout is not None:
                self._proc.stdout.close()
        except BrokenPipeError:
            pass

        try:
            if self._proc.stderr is not None:
                self._proc.stderr.close()
        except BrokenPipeError:
            pass

    def _is_alive_impl(self) -> bool:
        """Check if the process is alive"""
        return self.poll() is None

    def __str__(self) -> str:
        return f"'{self._filepath}' (PID={self._proc.pid})"


    #
    # Custom method
    #
    def poll(self) -> Optional[int]:
        """Check if the process has exited
        """
        if self._proc.poll() is None:
            return None

        if self._returncode is None:
            # First time to detect process exit
            self._returncode = self._proc.returncode
            name = signal_name(-self._returncode, detail=True)
            if name:
                name = ' --> ' + name

            logger_func = logger.info if self._returncode == 0 else logger.error
            logger_func(f"{str(self)} stopped with exit code " \
                            f"{self._returncode}{name}")

        return self._returncode

    @tube_is_open
    def wait(self, timeout: Optional[Union[int, float]]=None) -> int:
        """Wait until the process dies

        Wait until the process exits and get the status code.

        Returns:
            code (int): Status code of the process
        """
        return self._proc.wait(timeout)


Process = WinProcess if _is_windows else UnixProcess
process = Process # alias for the Process
