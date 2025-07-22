"""This package provides Process module for UNIX systems
"""
import fcntl
import os
import pty
import select
import subprocess
import tty
from logging import getLogger
from typing import List, Mapping, Optional, Union, cast
from ptrlib.debugger.unix import UnixProcessManager
from ptrlib.arch.linux.sig import signal_name
from ptrlib.binary.encoding import bytes2str
from .tube import Tube, tube_is_open

logger = getLogger(__name__)


class UnixProcess(Tube):
    """Unix process.
    """
    def __init__(self,
                 args: Union[bytes, str, List[Union[bytes, str]]],
                 env: Optional[Union[Mapping[bytes, Union[bytes, str]],
                                     Mapping[str, Union[bytes, str]]]]=None,
                 cwd: Optional[Union[bytes, str]]=None,
                 shell: Optional[bool]=None,
                 raw: bool=False,
                 stdin : Optional[int]=None,
                 stdout: Optional[int]=None,
                 stderr: Optional[int]=None,
                 **kwargs):
        """Create a UNIX process.

        Create a UNIX process and make a pipe.

        Args:
            args (str or List[str]): The program name and arguments to execute.
            env (Dict[str,str], optional): Environment variables in dictionary.
            cwd (str, optional): Current working directory.
            shell (bool, optional): Treat `args` as a shell command string if true.
            raw (bool, optional): Disable pty if true.
            stdin (int, optional): File descriptor for standard input.
            stdout (int, optional): File descriptor for standard output.
            stderr (int, optional): File descriptor for standard error.
            timeout (float, optional): Default timeout in second.

        Examples:
            ```
            p = Process("/bin/ls", cwd="/tmp")
            p = Process(["wget", "www.example.com"],
                        stderr=subprocess.DEVNULL)
            p = Process("cat /proc/self/maps", env={"LD_PRELOAD": "a.so"})
            ```
        """
        # NOTE: We need to initialize _current_timeout before super constructor
        #       because the super may call _settimeout_impl
        self._current_timeout = 0
        super().__init__(**kwargs)

        # Guess shell mode based on args
        if shell is None:
            if isinstance(args, (str, bytes)):
                progname = bytes2str(args)
                args = [progname]
                if ' ' in progname:
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
            elif isinstance(args, list):
                args = list(map(bytes2str, args))

        # Prepare stdio
        master = self._slave = None
        if not raw:
            master, self._slave = pty.openpty()
            tty.setraw(master)
            tty.setraw(self._slave)
            stdout = self._slave

        if stdin is None:
            stdin = subprocess.PIPE
        if stdout is None:
            stdout = subprocess.PIPE
        if stderr is None:
            stderr = subprocess.STDOUT

        # Open process
        assert isinstance(shell, bool), "`shell` must be boolean"
        try:
            self._proc = subprocess.Popen(
                args, cwd=cwd, env=env,
                shell=shell,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True
            )
        except FileNotFoundError as err:
            logger.error("Could not execute %s", args[0])
            raise err from None

        self._filepath = args[0]
        self._returncode = None

        # Duplicate master
        if master is not None:
            self._proc.stdout = os.fdopen(os.dup(master), 'r+b', 0)
            os.close(master)

        # Set in non-blocking mode
        if self._proc.stdout is not None:
            fd = self._proc.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        # Debugger interface
        self._process = UnixProcessManager(self.pid)

        logger.info("Successfully created a new process %s", str(self))
        self._init_done = True

    @property
    def returncode(self) -> Optional[int]:
        """Get the exit code of this process.
        None is returned if the process is still running.
        """
        return self._returncode

    @property
    def pid(self) -> int:
        """Get the process ID.
        """
        return self._proc.pid

    @property
    @tube_is_open
    def process(self) -> UnixProcessManager:
        """Get a `UnixProcessManager` instance for this process.
        """
        return self._process

    #
    # Implementation of Tube methods
    #
    def _settimeout_impl(self, timeout: Union[int, float]):
        """Set timeout.

        Args:
            timeout (float): Timeout seconds.
        """
        self._current_timeout = timeout

    def _recv_impl(self, size: int) -> bytes:
        """Receive raw data.

        Receive raw data of maximum `size` bytes through the pipe.

        Args:
            size (int): The maximum number of bytes to receive.

        Returns:
            bytes: The received data.
        """
        if self._proc.stdout is None:
            return b''

        if self._current_timeout == 0:
            timeout = None
        else:
            timeout = self._current_timeout

        if timeout is None:
            while self.is_alive():
                if self._is_output_alive(self._POLL_TIMEOUT):
                    break

        else:
            if not self._is_output_alive(timeout):
                raise TimeoutError("Timeout (_recv_impl)", b'') from None

        try:
            data = self._proc.stdout.read(size)
        except subprocess.TimeoutExpired:
            raise TimeoutError("Timeout (_recv_impl)", b'') from None

        if data is None:
            raise ConnectionAbortedError("Connection closed (_recv_impl)", b'') from None

        return data

    def _send_impl(self, data: bytes) -> int:
        """Send raw data.

        Args:
            data (bytes): Data to send.

        Returns:
            int: The number of bytes sent. -1 if stdin is closed.

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error
        """
        if self._proc.stdin is None:
            return -1

        try:
            n_written = self._proc.stdin.write(data)
            self._proc.stdin.flush()
            return n_written

        except IOError as err:
            logger.error("Broken pipe: %s", str(self))
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
        if self._proc.stdin is not None:
            self._proc.stdin.close()

    def _close_impl(self):
        """Close process
        """
        if self._is_alive_impl():
            self._proc.kill()
            self._proc.wait()
            logger.info("%s killed by `close`", str(self))

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
        return self._is_output_alive() or self.poll() is None

    def __str__(self) -> str:
        return f"'{self._filepath}' (PID={self._proc.pid})"

    #
    # Custom method
    #
    def _is_output_alive(self, timeout: Union[int, float]=0) -> bool:
        """Check if either stdout or stderr is alive
        """
        watch = list(filter(lambda f: f is not None, [self._proc.stdout, self._proc.stderr]))
        if len(watch) == 0:
            return False

        ready, [], [] = select.select(watch, [], [], timeout)
        return len(ready) != 0

    def poll(self) -> Optional[int]:
        """Check if the process has exited
        """
        if self._proc.poll() is None:
            return None

        if self._returncode is None:
            # First time to detect process exit
            self._returncode = returncode = cast(int, self._proc.returncode)
            name = signal_name(-returncode, detail=True)
            if name:
                name = ' --> ' + name

            logger_func = logger.info if self._returncode == 0 else logger.error
            logger_func("%s stopped with exit code %d%s", str(self), self._returncode, name)

        return self._returncode

    @tube_is_open
    def wait(self, timeout: Optional[Union[int, float]]=None) -> int:
        """Wait until the process dies

        Wait until the process exits and get the status code.

        Returns:
            code (int): Status code of the process
        """
        return self._proc.wait(timeout)


__all__ = ['UnixProcess']
