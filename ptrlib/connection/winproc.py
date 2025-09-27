import contextlib
import ctypes
import ctypes.wintypes as wt
import errno
import msvcrt
import os
import shlex
import subprocess
import time
from logging import getLogger

from .tube import Tube


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# BOOL PeekNamedPipe(
#   HANDLE hNamedPipe,
#   LPVOID lpBuffer,
#   DWORD  nBufferSize,
#   LPDWORD lpBytesRead,
#   LPDWORD lpTotalBytesAvail,
#   LPDWORD lpBytesLeftThisMessage
# );
kernel32.PeekNamedPipe.argtypes = [
    wt.HANDLE, ctypes.c_void_p, wt.DWORD,
    ctypes.POINTER(wt.DWORD),
    ctypes.POINTER(wt.DWORD),
    ctypes.POINTER(wt.DWORD),
]
kernel32.PeekNamedPipe.restype = wt.BOOL

# BOOL GenerateConsoleCtrlEvent(DWORD dwCtrlEvent, DWORD dwProcessGroupId);
kernel32.GenerateConsoleCtrlEvent.argtypes = [wt.DWORD, wt.DWORD]
kernel32.GenerateConsoleCtrlEvent.restype = wt.BOOL

ERROR_BROKEN_PIPE = 109
CTRL_C_EVENT = 0
CTRL_BREAK_EVENT = 1

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000


def _last_error() -> int:
    return ctypes.get_last_error() or ctypes.get_last_error()


def _peek_named_pipe_bytes_available(h: int) -> int:
    """Return available bytes to read on a pipe HANDLE. 0 on EOF.

    Raises:
        OSError: If PeekNamedPipe fails for reasons other than BROKEN_PIPE.
    """
    avail = wt.DWORD(0)
    ok = kernel32.PeekNamedPipe(
        wt.HANDLE(h), None, 0, None, ctypes.byref(avail), None
    )
    if not ok:
        err = _last_error()
        if err == ERROR_BROKEN_PIPE:
            return 0  # EOF (orderly close)
        raise OSError(err, "PeekNamedPipe failed")
    return int(avail.value)


class WinProcess(Tube):
    """Windows process runner with pipe-based I/O (no PTY).

    This class spawns a process via `subprocess.Popen` with anonymous pipes for
    stdin/stdout[/stderr]. On Windows, pipes are not selectable; therefore,
    reads are implemented using `PeekNamedPipe` to check how many bytes can be
    read without blocking, honoring the per-tube timeout.

    Example:
    >>> p = WinProcess("cmd /c type")
    >>> p.sendline("hello")
    >>> print(p.recvline().decode().strip())
    hello
    >>> p.close()

    Args:
        args: Command string or argv list. If `shell=True`, string is run via shell.
        env: Optional environment vars for the child.
        cwd: Optional working directory.
        shell: Run through the shell.
        merge_stderr: If True, redirect stderr -> stdout.
        creationflags: Extra `subprocess.Popen` creation flags (OR'ed).
        new_process_group: Add `CREATE_NEW_PROCESS_GROUP` (required for CTRL_BREAK).
        no_window: Add `CREATE_NO_WINDOW` to avoid a transient console window.
        quiet: Suppress Tube-level logs.

    Raises:
        FileNotFoundError: Executable not found (when `shell=False`).
        OSError: Any OS-level failure on spawn.
        ValueError: Invalid arguments combination.
    """

    def __init__(self,
                 args: str | list[str],
                 env: dict[str, str] | None = None,
                 cwd: str | None = None,
                 shell: bool = False,
                 *,
                 merge_stderr: bool = True,
                 creationflags: int | None = None,
                 new_process_group: bool = True,
                 no_window: bool = True,
                 **kwargs):
        self._proc: subprocess.Popen | None = None
        self._timeout: float | None = None
        self._stdin_fd: int = -1
        self._stdout_fd: int = -1
        self._stderr_fd: int = -1
        self._h_stdout: int = 0  # Windows HANDLE (for PeekNamedPipe)
        self._h_stderr: int = 0

        self._args = args if isinstance(args, list) else shlex.split(args)
        self._filepath = self._args[0]
        stdin = subprocess.PIPE
        stdout = subprocess.PIPE
        stderr = subprocess.STDOUT if merge_stderr else subprocess.PIPE

        super().__init__(**kwargs)
        self._logger = getLogger(__name__)
        self._newline = [b'\r\n']

        flags = 0
        if creationflags:
            flags |= int(creationflags)
        if new_process_group:
            flags |= CREATE_NEW_PROCESS_GROUP
        if no_window and not shell:
            # If shell=True, cmd.exe may still flash a window; prefer STARTUPINFO then.
            flags |= CREATE_NO_WINDOW

        # Hide window also for shell=True cases
        startupinfo = None
        if no_window:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE

        # Spawn
        self._proc = subprocess.Popen(
            self._args if not shell else " ".join(shlex.quote(a) for a in self._args),
            shell=shell,
            env=env,
            cwd=cwd,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            creationflags=flags,
            startupinfo=startupinfo,
            bufsize=0,
        )

        # File descriptors
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None

        self._stdin_fd = self._proc.stdin.fileno()
        self._stdout_fd = self._proc.stdout.fileno()
        self._h_stdout = msvcrt.get_osfhandle(self._stdout_fd)

        if not merge_stderr and self._proc.stderr is not None:
            self._stderr_fd = self._proc.stderr.fileno()
            self._h_stderr = msvcrt.get_osfhandle(self._stderr_fd)

        self._log_info(f"Successfully created a new process {str(self)}")

    def __str__(self) -> str:
        try:
            return f"WinProcess(PID={self.pid})"
        except ChildProcessError:
            return "WinProcess(<terminated>)"

    # --- Properties -------------------------------------------------------

    @property
    def returncode(self) -> int:
        """Get the return code of the spawned process.
        """
        return self.wait()

    @property
    def pid(self) -> int:
        """Child process ID.

        Raises:
            ChildProcessError: If process object is gone.
        """
        if self._proc is None:
            raise ChildProcessError("Process has terminated")
        return self._proc.pid

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
            self._log_info(f"Process {str(self)} stopped with exit code {code}")
        return code

    def kill(self, force: bool = False, wait: float | bool = True, timeout: float = 1.0) -> None:
        """Terminate the process.

        Args:
            force: If True, use `kill()` (TerminateProcess). Else `terminate()`.
            wait: If True, wait up to `timeout` seconds. If float, wait that many seconds.
            timeout: Max seconds to wait when `wait is True`.

        Raises:
            (never): Best-effort termination.
        """
        if self._proc is None:
            return
        if force:
            with contextlib.suppress(Exception):
                self._proc.kill()
        else:
            with contextlib.suppress(Exception):
                self._proc.terminate()

        if wait is True:
            wait_timeout = timeout
        elif isinstance(wait, (int, float)):
            wait_timeout = float(wait)
        else:
            wait_timeout = None

        if wait_timeout is not None:
            with contextlib.suppress(Exception):
                self._proc.wait(timeout=wait_timeout)

    # --- Abstracts --------------------------------------------------------

    @property
    def _logname_impl(self) -> str:
        """Get the log file name for this process.
        """
        return f'Process({self._filepath})'

    def _recv_impl(self, blocksize: int) -> bytes:
        """Receive up to ``blocksize`` bytes from the child.

        Implementation detail (Windows):
            Uses `PeekNamedPipe` on stdout to determine available bytes without
            blocking; if none, it waits until data arrives, the process exits,
            or the timeout elapses.

        Returns:
            bytes: Data read. Empty bytes are not returned unless EOF is imminent.

        Raises:
            EOFError: Child closed the pipe (EOF) or process terminated.
            TimeoutError: No data became available within the timeout.
            BrokenPipeError: Pipe broken while reading (rare).
            OSError: Other OS-level errors (e.g., PeekNamedPipe failure).
        """
        assert blocksize > 0, "BUG: blocksize must be positive"

        if self._proc is None or self._proc.stdout is None:
            raise EOFError("Connection has been closed")

        deadline = None if self._timeout is None else (time.monotonic() + self._timeout)

        while True:
            # 1) Process exit => EOF
            if self._proc.poll() is not None:
                # Drain any remaining bytes once
                avail = _peek_named_pipe_bytes_available(self._h_stdout)
                if avail > 0:
                    to_read = min(blocksize, avail)
                    return os.read(self._stdout_fd, to_read)
                raise EOFError("Connection has been closed")

            # 2) See how much we can read now
            try:
                avail = _peek_named_pipe_bytes_available(self._h_stdout)
            except OSError as e:
                if e.errno == ERROR_BROKEN_PIPE:
                    raise EOFError("Connection has been closed") from e
                raise

            if avail > 0:
                to_read = min(blocksize, avail)
                try:
                    data = os.read(self._stdout_fd, to_read)
                except OSError as e:
                    if e.errno in (errno.EPIPE, ERROR_BROKEN_PIPE):
                        raise EOFError("Connection has been closed") from e
                    raise
                if not data:
                    # Broken or EOF
                    raise EOFError("Connection has been closed") from e
                return data

            # 3) Wait for more data or timeout
            if deadline is None:
                # Blocking semantics: brief sleep to yield (Windows pipe has no waitable read)
                time.sleep(0.005)
                continue

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Read operation timed out ({self._timeout}s)")
            # Sleep a tiny slice to avoid busy loop
            time.sleep(min(0.005, remaining))

    def _send_impl(self, data: bytes) -> int:
        """Send a chunk to child's stdin (single syscall).

        Returns:
            int: Number of bytes written (>= 0, rarely less than len(data) on Windows).

        Raises:
            BrokenPipeError: Child closed stdin / pipe broken.
            TimeoutError: Not used on Windows anonymous pipe (writes typically block rarely).
            OSError: Other OS-level write errors.
        """
        if self._proc is None or self._proc.stdin is None:
            raise BrokenPipeError("Connection has been closed")

        try:
            n = os.write(self._stdin_fd, data)
            if n == 0:
                raise BrokenPipeError("Connection has been closed")
            return n

        except OSError as e:
            if e.errno in (errno.EPIPE, ERROR_BROKEN_PIPE):
                raise BrokenPipeError("Connection has been closed") from e
            raise

    def _close_impl(self):
        """Terminate the process and close all handles (best-effort).
        """
        # Close stdio pipes (best-effort)
        if self._proc is not None:
            for s in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
                if s is not None:
                    with contextlib.suppress(Exception):
                        s.close()

        # Terminate if still alive
        if self._proc is not None and self._proc.poll() is None:
            with contextlib.suppress(Exception):
                self._proc.terminate()  # graceful
            # small grace
            with contextlib.suppress(Exception):
                self._proc.wait(timeout=0)
            if self._proc.poll() is None:
                with contextlib.suppress(Exception):
                    self._proc.kill()  # force
                with contextlib.suppress(Exception):
                    self._proc.wait(timeout=0)

        self._proc = None
        self._stdin_fd = self._stdout_fd = self._stderr_fd = -1
        self._h_stdout = self._h_stderr = 0

    def _close_recv_impl(self):
        """Close the receive side (stdout/stderr) of the pipe.

        Note:
            On Windows anonymous pipes, half-close is supported per-direction.
        """
        if self._proc is None:
            return

        if self._proc.stdout is not None:
            with contextlib.suppress(Exception):
                self._proc.stdout.close()
        if self._proc.stderr is not None:
            with contextlib.suppress(Exception):
                self._proc.stderr.close()

        self._stdout_fd = self._stderr_fd = -1
        self._h_stdout = self._h_stderr = 0

    def _close_send_impl(self):
        """Close the send side (stdin) of the pipe.
        """
        if self._proc is None:
            return

        if self._proc.stdin is not None:
            with contextlib.suppress(Exception):
                self._proc.stdin.close()

        self._stdin_fd = -1

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
        """Return True while the process is running (exit code is None)."""
        return self._proc is not None and self._proc.poll() is None

    # --- Windows-specific utilities --------------------------------------

    def available(self) -> int:
        """Return how many bytes are immediately readable from child's stdout.

        Returns:
            int: Available bytes (0 implies nothing now; may also mean EOF if child exited).

        Raises:
            OSError: If PeekNamedPipe fails for reasons other than BROKEN_PIPE.
        """
        if self._h_stdout:
            return _peek_named_pipe_bytes_available(self._h_stdout)
        return 0

    def send_ctrl_break(self) -> bool:
        """Attempt to deliver CTRL_BREAK to the child's process group.

        Returns:
            bool: True if the API call succeeded (not a guarantee the child handled it).

        Notes:
            - Requires the child to be started with `CREATE_NEW_PROCESS_GROUP`.
            - Also requires the child to **share the same console**. When we use pipes
              and `CREATE_NO_WINDOW`, there is typically *no* shared console, so this
              may not have effect. Consider starting without `no_window` and without
              `shell=True` if you need console control events.

        Raises:
            (never)
        """
        if self._proc is None:
            return False
        # Group ID is child's PID when CREATE_NEW_PROCESS_GROUP is used.
        return bool(kernel32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, self._proc.pid))
