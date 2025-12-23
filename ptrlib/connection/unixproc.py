"""Process communication abstraction using PTY or pipes.

This module provides the `Process` class, which enables non-blocking communication
with a spawned Unix process, preferring the use of a pseudo-terminal (PTY) when possible.
It supports sending and receiving data, process lifecycle management, and flexible
configuration of environment, working directory, and I/O behavior.

Classes:
    Process: Inherits from `Tube`. Manages a subprocess with PTY or pipe-based I/O,
        supporting non-blocking reads/writes, timeouts, and process control.
"""
import contextlib
import errno
import fcntl
import os
import signal
import tty
import select
import shlex
import termios
import subprocess
from logging import getLogger
from ptrlib.debugger.unix import UnixProcessManager
from ptrlib.binary.packing import p16
from ptrlib.os.linux import signal_name
from .tube import Tube


TcAttrT = list[int | list[int | bytes]]

class UnixProcess(Tube):
    """Communication with a Unix process (PTY preferred, non-blocking I/O).

    Example:

    .. code-block:: python

        from ptrlib import Process

        Process("/bin/cat").sh()

        files = Process(["ls", "-lha"], cwd="/").recvall()

        chall = "example"
        sol = (
            Process(["python", "solve.py"], env={"CHALL": chall})
            .recvregex(r"Solution: (.+)")
            .group(1)
        )
    """
    def __init__(self,
                 args: str | list[str],
                 env: dict[str, str] |None = None,
                 cwd: str | None = None,
                 shell: bool = False,
                 merge_stderr: bool = True,
                 use_tty: bool = False,
                 is_raw: bool = True,
                 **kwargs):
        self._fd_r: int = -1
        self._fd_w: int = -1
        self._args: list[str]
        self._raw_args: str | list[str] = args
        self._pty_slave: int = -1
        self._pty_master: int = -1
        self._saved_termios: TcAttrT | None = None
        self._timeout: float | None = None
        self._proc: subprocess.Popen | None = None

        self._workdir = os.path.realpath(cwd) if cwd else os.getcwd()
        self._args = args if isinstance(args, list) else shlex.split(args)
        self._env = os.environ.copy() if env is None else env
        self._shell = shell
        self._filepath = self._args[0]

        super().__init__(**kwargs)
        self._logger = getLogger(__name__)

        self._spawn_process(merge_stderr, use_tty, is_raw)
        self._set_nonblocking(self._fd_r)
        self._set_nonblocking(self._fd_w)

        self._process = UnixProcessManager(self.pid)

        self._log_info(f"Successfully created a new process {str(self)}")

    def __del__(self):
        try:
            self._close_impl()
        finally:
            super().__del__()

    def __str__(self) -> str:
        try:
            return f"'{self._filepath}' (PID={self.pid})"
        except ChildProcessError:
            return f"'{self._filepath}' (terminated)"

    # --- Properties -------------------------------------------------------

    @property
    def returncode(self) -> int:
        """Get the return code of the spawned process.
        """
        return self.wait()

    @property
    def pid(self) -> int:
        """Get the process ID (PID) of the spawned process.

        Raises:
            ChildProcessError: If the process has terminated.
        """
        if self._proc is None:
            raise ChildProcessError("Process has terminated")
        return self._proc.pid

    @property
    def process(self) -> UnixProcessManager:
        """Get a `UnixProcessManager` instance for this process.
        """
        if self._proc is None:
            raise ChildProcessError("Process has terminated")
        return self._process

    # --- Abstracts --------------------------------------------------------

    @property
    def _logname_impl(self) -> str:
        """Get the log file name for this process.
        """
        return f'Process({self._filepath})'

    def _recv_impl(self, blocksize: int):
        """Read up to ``blocksize`` bytes from the process.

        Raises:
            EOFError: The process has closed its output stream.
            TimeoutError: The operation timed out.
            OSError: System error.
        """
        assert blocksize > 0, "BUG: blocksize must be positive"

        if self._fd_r == -1:
            raise EOFError("Connection has been closed")

        while True:
            r, _, _ = select.select([self._fd_r], [], [], self._timeout)
            if not r:
                raise TimeoutError(f"Read operation timed out ({self._timeout}s)")
            try:
                data = os.read(self._fd_r, blocksize)
                return data
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                if e.errno in (errno.EIO, errno.EBADF):
                    raise EOFError("Connection has been closed") from e
                raise

    def _send_impl(self, data: bytes) -> int:
        """Send raw data.

        Args:
            data (bytes): Data to send.

        Returns:
            int: The number of bytes sent. -1 if stdin is closed.

        Raises:
            BrokenPipeError: The process has closed its input stream.
            TimeoutError: The operation timed out.
            OSError: System error.
        """
        if self._fd_w == -1:
            raise BrokenPipeError("Connection has been closed")

        total = 0
        view = memoryview(data)
        while total < len(view):
            _, w, _ = select.select([], [self._fd_w], [], self._timeout)
            if not w:
                raise TimeoutError("Timeout (_send_impl)")

            try:
                n_written = os.write(self._fd_w, view[total:])
                if n_written == 0:
                    raise BrokenPipeError("Connection has been closed")
                total += n_written

            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                if e.errno in (errno.EPIPE, errno.EBADF):
                    raise BrokenPipeError("Connection has been closed") from e
                raise

        return total

    def _close_impl(self):
        """Terminate the process and free all resources.
        """
        # Cleanup process
        if self._proc is not None:
            if self.poll() is None:
                with contextlib.suppress(Exception):
                    self._proc.terminate()
                try:
                    self.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(Exception):
                        self._proc.kill()
                    with contextlib.suppress(Exception):
                        self.wait(timeout=0.1)

        # Cleanup fds
        if self._fd_r != -1:
            with contextlib.suppress(OSError):
                os.close(self._fd_r)
            self._fd_r = -1

        if self._fd_w != -1:
            with contextlib.suppress(OSError):
                os.close(self._fd_w)
            self._fd_w = -1

        if self._pty_slave != -1:
            with contextlib.suppress(OSError):
                os.close(self._pty_slave)
            self._pty_slave = -1

        self._pty_master = -1

        # Close subprocess streams
        if self._proc is not None:
            for stream in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
                if stream is not None:
                    with contextlib.suppress(OSError):
                        stream.close()

    def _close_recv_impl(self):
        """Close the receive end of the connection (half-close).
        """
        if self._proc is not None:
            if self._proc.stdout:
                self._proc.stdout.close()
            if self._proc.stderr:
                self._proc.stderr.close()

    def _close_send_impl(self):
        """Close the send end of the connection (half-close).
        """
        if self._proc is not None:
            if self._proc.stdin:
                self._proc.stdin.close()

    def _settimeout_impl(self, timeout: float):
        """Set socket timeout (Tube semantics).

        Args:
            timeout: Negative -> blocking; non-negative -> seconds.

        Raises:
            OSError: If the underlying socket rejects the timeout (rare).
            ValueError: Invalid timeout value.
        """
        if timeout < 0:
            self._timeout = None
        else:
            self._timeout = timeout

    def _gettimeout_impl(self) -> float:
        """Get current timeout (Tube semantics).

        Returns:
            float: -1 for blocking (no timeout), or the current timeout in seconds.
        """
        if self._timeout is None:
            return -1
        return self._timeout

    def _is_alive_impl(self) -> bool:
        """Check if the process is alive.

        Returns:
            bool: True if the process is alive, False otherwise.
        """
        return self.poll() is None

    # --- Process operations -----------------------------------------------

    def poll(self) -> int | None:
        """Return the process returncode if finished, else None.
        """
        return None if self._proc is None else self._proc.poll()

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the process to terminate and return its exit code.
        """
        if self._proc is None:
            return 0
        code = self._proc.wait(timeout)

        if self._is_alive:
            self._is_alive = False
            name = signal_name(-code, detail=True)
            if name:
                name = ' --> ' + name
            self._log_info(f"Process {str(self)} stopped with exit code {code}{name}")
        return code

    def kill(self,
            sig: int = signal.SIGTERM,
            *,
            killall: bool = False,
            wait: bool | float = False,
            force_sig: int = signal.SIGKILL,
            timeout: float = 1.0) -> None:
        """Send a signal to the process (or its process group) and optionally wait.

        Args:
            sig: Signal to send initially (default: SIGTERM).
            killall: If True, signal the **process group** (best-effort). Falls back to
                    the single PID when a process group is not available.
            wait: If True, wait for termination. If a float, wait up to that many seconds.
            force_sig: Signal to send if the process did not exit within the wait timeout.
            timeout: Max seconds to wait when ``wait is True`` (ignored if ``wait`` is a float).

        Raises:
            PermissionError: If signaling is not permitted by the OS.
            RuntimeError: If called when no process has been spawned.
            OSError: Other OS-level signaling errors.
        """
        if self._proc is None:
            raise RuntimeError("No process to signal")

        # Prefer signaling the process group when requested (PTY path creates a new session).
        pid = self._proc.pid
        try:
            if killall:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(pid, sig)
            else:
                os.kill(pid, sig)
        except ProcessLookupError:
            # Already gone
            return

        # Wait behavior
        if wait is True:
            wait_timeout = timeout
        elif isinstance(wait, (int, float)):
            wait_timeout = float(wait) 
        else:
            return

        try:
            self._proc.wait(timeout=wait_timeout)
        except Exception:
            # Escalate with force signal
            try:
                if killall:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(pid, force_sig)
                else:
                    os.kill(pid, force_sig)
            except ProcessLookupError:
                pass
            with contextlib.suppress(Exception):
                self._proc.wait(timeout=wait_timeout)

    def is_alive(self) -> bool:
        """Return True if the process is still running, False otherwise."""
        return (self._proc is not None) and (self._proc.poll() is None)

    def resize_pty(self, cols: int, rows: int) -> None:
        """Resize the process PTY window.

        Args:
            cols: Number of columns.
            rows: Number of rows.

        Raises:
            RuntimeError: If no PTY backend is active.
            OSError: If the ioctl fails on the underlying PTY.
        """
        if self._pty_master == -1:
            raise RuntimeError("PTY backend is not active (use_tty=False?)")

        # struct winsize { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; }
        winsz = p16([rows, cols, 0, 0])
        fcntl.ioctl(self._pty_master, termios.TIOCSWINSZ, winsz)

    def set_raw(self, enable: bool) -> None:
        """Toggle RAW mode on the PTY.

        When enabled, disables ICANON/ECHO and output post-processing (ONLCR),
        making the PTY behave like a raw pipe (no CRLF translation).

        Args:
            enable: True to enable RAW mode; False to restore previous cooked settings.

        Raises:
            RuntimeError: If no PTY backend is active.
            OSError: If termios operations fail on the PTY.
        """
        if self._pty_master == -1:
            raise RuntimeError("PTY backend is not active (use_tty=False?)")

        # Save/restore termios attributes on first toggle.
        if enable:
            if self._saved_termios is None:
                self._saved_termios = termios.tcgetattr(self._pty_master)
            tty.setraw(self._pty_master, when=termios.TCSANOW)
        else:
            if self._saved_termios is not None:
                termios.tcsetattr(self._pty_master, termios.TCSANOW, self._saved_termios)

    # --- Helpers ----------------------------------------------------------

    def _spawn_process(self, merge_stderr: bool, use_tty: bool, is_raw: bool):
        stdin = subprocess.PIPE
        stdout = subprocess.PIPE
        stderr = subprocess.STDOUT if merge_stderr else subprocess.DEVNULL

        def setup_tty():
            # Become session leader so we can set controlling terminal
            os.setsid()
            # Make slave the controlling TTY
            fcntl.ioctl(self._pty_slave, termios.TIOCSCTTY, 0)
            # Dup slave to stdio
            os.dup2(self._pty_slave, 0)
            os.dup2(self._pty_slave, 1)
            os.dup2(self._pty_slave, 2)
            # Close master in child if leaked
            with contextlib.suppress(OSError):
                os.close(self._pty_master)

        if use_tty:
            self._pty_master, self._pty_slave = os.openpty()
            if is_raw:
                tty.setraw(self._pty_slave, when=termios.TCSANOW)

        if self._shell:
            if isinstance(self._raw_args, str):
                popen_args = self._raw_args
            else:
                popen_args = " ".join(shlex.quote(arg) for arg in self._raw_args)
        else:
            popen_args = self._args

        # Determine if we should detach from the current session (no controlling TTY).
        # SSH with SSH_ASKPASS needs this on older OpenSSH builds where a controlling
        # TTY (accessible via /dev/tty) suppresses askpass. The SSH wrapper sets
        # PTRLIB_START_NEW_SESSION=1 when a password is provided on POSIX.
        start_new_sess = False
        try:
            start_new_sess = (not use_tty) and (str(self._env.get("PTRLIB_START_NEW_SESSION", "0")) == "1")
        except Exception:
            start_new_sess = False

        # pylint: disable-next=subprocess-popen-preexec-fn
        self._proc = subprocess.Popen(
            popen_args,
            shell=self._shell,
            cwd=self._workdir,
            env=self._env,
            preexec_fn=setup_tty if use_tty else None,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            close_fds=True,
            bufsize=0,
            start_new_session=start_new_sess,
        )

        with contextlib.suppress(OSError):
            os.close(self._pty_slave)

        if use_tty:
            self._fd_r = self._pty_master
            self._fd_w = self._pty_master
        else:
            assert self._proc.stdout is not None
            assert self._proc.stdin is not None
            self._fd_r = self._proc.stdout.fileno()
            self._fd_w = self._proc.stdin.fileno()

    @staticmethod
    def _set_nonblocking(fd: int):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if not flags & os.O_NONBLOCK:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
