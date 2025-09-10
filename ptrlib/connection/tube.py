"""Abstract base class for bidirectional, buffered byte-stream communication.

The Tube class provides a unified interface for interacting with various types of I/O streams
(e.g., sockets, subprocesses, pipes) in a thread-safe and buffered manner. It supports high-level
methods for sending and receiving data, line-based and regex-based reading, interactive sessions,
and timeout management. Subclasses must implement low-level transport-specific hooks.

Key features:
- Buffered, thread-safe I/O with support for custom delimiters and regex patterns.
- Flexible send/receive methods, including sendline, recvall, recvline, and recvuntil.
- Interactive mode for user-driven sessions (with TTY/raw support).
- Configurable debugging and logging.
- Abstract methods for transport-specific implementations.
"""
import abc
import contextlib
import os
import re
import select
import sys
import threading
import time
import typing
import unicodedata
from logging import getLogger
from pathlib import Path

from ptrlib.console import Color
from ptrlib.binary.encoding import str2bytes, hexdump
from ptrlib.filestruct.pcap import PcapFile

logger = getLogger(__name__)


DebugModeT = typing.Literal['none', 'plain', 'hex']
DelimiterT = str | bytes | list[str] | list[bytes] | list[str | bytes]
RegexDelimiterT = str | bytes | re.Pattern | list[str | bytes | re.Pattern]
AtomicSendT = int | float | str | bytes

def _is_tty_stdin() -> bool:
    with contextlib.suppress(Exception):
        return sys.stdin.isatty()
    return False

def _is_posix() -> bool:
    return os.name == "posix"

class Tube(metaclass=abc.ABCMeta):
    """Abstract base for bidirectional, buffered byte-stream communication.

    Subclasses must implement the low-level hooks:
    - `_recv_impl`
    - `_send_impl`
    - `_close_impl`
    - `_close_recv_impl`
    - `_close_send_impl`
    - `_settimeout_impl`
    - `_gettimeout_impl`

    High-level methods (recv*, send*) operate against an internal buffer and respect
    the instance-wide timeout via the `timeout(...)` context manager.
    """
    def __init__(self,
                 debug: bool | DebugModeT = False,
                 pcap: str | None = None,
                 quiet: bool = False):
        self._debug: DebugModeT
        self._buffer = b''
        self._mutex = threading.Lock()
        self._prompt: str = '[ptrlib]$ '
        self._is_alive: bool = True
        self._quiet: bool = quiet
        self._logger = getLogger(__name__) # Fallback logger

        # Configuration options
        self._newline: list[bytes] = [b'\n']
        self.debug = debug # Let setter validate and normalize it

        # Logging target
        if pcap is None:
            path = Path(f"/tmp/ptrlib/log-{self._sanitize_filename(self._logname_impl)}.pcap")
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            path = Path(pcap)

        self._pcap: PcapFile = PcapFile(path)

    def __del__(self):
        self.close()

    def _log_info(self, message: str, *args, stacklevel: int = 2):
        if not self._quiet:
            self._logger.info(message, stacklevel=stacklevel, *args)

    def _log_warning(self, message: str, *args, stacklevel: int = 2):
        if not self._quiet:
            self._logger.warning(message, stacklevel=stacklevel, *args)

    def _log_error(self, message: str, *args, stacklevel: int = 2):
        if not self._quiet:
            self._logger.error(message, stacklevel=stacklevel, *args)

    # --- Properties -------------------------------------------------------

    @property
    def newline(self) -> bytes:
        """A byte sequence considered as newline terminators.

        Examples:
            ```
            p = Process(["wine", "a.exe"])
            p.newline = [b"\\n", b"\\r\\n"]
            sock = Socket("localhost", 80)
            sock.newline = "\\r\\n"
            ```
        """
        return self._newline[0]

    @property
    def newlines(self) -> list[bytes]:
        """List of byte sequences considered as newline terminators.

        Examples:
            ```
            p = Process(["wine", "a.exe"])
            p.newline = [b"\\n", "\\r\\n"]
            p.newline  # b"\n"
            p.newlines # b"\r\n"
            ```
        """
        return self._newline

    @newline.setter
    def newline(self, value: DelimiterT):
        """Set newline delimiter(s).

        Args:
            value: A single delimiter (str/bytes) or a list of delimiters.
                   Strings are encoded by `str2bytes`.

        Raises:
            ValueError: If the newline list is empty.
        """
        if isinstance(value, list):
            if len(value) == 0:
                raise ValueError("The newline list must not be empty")
            self._newline = [str2bytes(v) for v in value]
        else:
            self._newline = [str2bytes(value)]

    @property
    def debug(self) -> str:
        """Debug mode for I/O tracing.

        When enabled, incoming and outgoing data is printed.

        Values:
        - 'none'  : Disable debugging.
        - 'plain' : Print incoming bytes as UTF-8.
        - 'hex'   : Print incoming bytes as a hexdump-like view.
        - True  -> 'hex'
        - False -> 'none'

        Examples:
            ```
            sock = Socket("...", debug=True)
            sock.debug = False
            sock.debug = 'plain'
            sock.debug = 'hex'
            ```
        """
        return self._debug

    @debug.setter
    def debug(self, value: bool | DebugModeT):
        if isinstance(value, bool):
            self._debug = 'hex' if value else 'none'
        elif isinstance(value, str):
            if value in ('none', 'plain', 'hex'):
                self._debug = value
            else:
                raise ValueError(f"expected 'none', 'plain', or 'hex', not {repr(value)}")
        else:
            raise TypeError(f"expected bool or str, not {type(value)}")

    @property
    def prompt(self) -> str:
        """Prompt string displayed in the interactive mode.
        """
        return self._prompt

    @prompt.setter
    def prompt(self, value: str):
        self._prompt = value

    @property
    def pcap(self) -> PcapFile:
        """PCAP file for the connection.
        """
        return self._pcap

    # --- Receive methods --------------------------------------------------

    def recv(self,
             blocksize: int = 4096,
             timeout: int | float = -1) -> bytes:
        """Receive up to ``blocksize`` bytes.

        Args:
            blocksize: Maximum size for each low-level read.
            timeout: Timeout for each low-level read operation.

        Behavior:
            - If the internal buffer holds data, return up to ``blocksize`` bytes from it.
            - If the buffer is empty, perform a single low-level read
              via ``_recv_impl(blocksize)`` under the timeout context.

        Returns:
            bytes: Data received from the stream.

        Raises:
            EOFError: If the connection is closed before any data is received.
            ValueError: If ``blocksize`` is negative.
            TubeTimeout: If the operation timed out.
            OSError: If a system error occurred.
        """
        if blocksize < 0:
            raise ValueError(f"blocksize must be >= 0, not {blocksize}")
        if blocksize == 0:
            return b''

        if self._is_alive and not self._is_alive_impl():
            # First time detection of dead tube
            self._is_alive = False
            self._log_warning(f"Connection {str(self)} is dead")

        with self._mutex:
            if self._buffer:
                out, self._buffer = self._buffer[:blocksize], self._buffer[blocksize:]
                return self._trace_incoming(out)

        # Buffer empty: perform a single recv from the underlying transport.
        with self.timeout(timeout):
            try:
                chunk = self._recv_impl(blocksize)
            except TimeoutError as e:
                raise TubeTimeout(str(e), buffered=self._buffer) from None
        # Do not store into the buffer here; return what we got.
        return self._trace_incoming(chunk)

    def recvall(self,
                size: int = -1,
                blocksize: int = 4096,
                timeout: int | float = -1) -> bytes:
        """Receive all requested data.

        Args:
            size: Number of bytes to read.
                  - If ``size >= 0``, read **exactly** ``size`` bytes. If EOF occurs first,
                    raise ``EOFError``.
                  - If ``size == -1``, read until EOF and return everything, including
                    previously buffered bytes.
            blocksize: Maximum size for each low-level read.
            timeout: Timeout for each low-level read operation.

        Returns:
            bytes: Data received from the stream.

        Raises:
            EOFError: When ``size >= 0`` but the connection ends before enough data is received.
            ValueError: If ``size < -1`` or ``blocksize`` is negative.
            TubeTimeout: If ``size >= 0`` and the operation timed out.
            OSError: If ``size >= 0`` and a system error occurred.
        """
        if size < -1:
            raise ValueError(f"size must be -1 or >= 0, not {size}")
        if blocksize < 0:
            raise ValueError(f"blocksize must be >= 0, not {blocksize}")

        out = bytearray()
        if size == -1:
            # Read until EOF.
            while True:
                try:
                    chunk = self.recv(blocksize, timeout=timeout)
                except (EOFError, OSError, TubeTimeout):
                    break
                out += chunk
            return bytes(out)

        # Read exactly 'size' bytes.
        while len(out) < size:
            try:
                chunk = self.recv(min(blocksize, size - len(out)), timeout=timeout)
            except TubeTimeout as e:
                raise TubeTimeout(str(e), buffered=out) from None
            out += chunk
        return bytes(out)

    def recvline(self,
                 blocksize: int = 4096,
                 timeout: int | float = -1,
                 drop: bool = True,
                 consume: bool = True) -> bytes:
        """Read until any configured newline delimiter is encountered.

        Args:
            blocksize: Maximum size for each low-level read attempt.
            timeout: Timeout for each low-level read operation.
            drop: If True, exclude the newline delimiter from the returned bytes.
            consume: If True, remove the delimiter from the internal buffer.

        Returns:
            bytes: Data up to (and optionally including) the newline delimiter.

        Raises:
            EOFError: If the connection is closed before a newline is received.
            ValueError: If ``blocksize`` is negative.
            TubeTimeout: If the operation timed out.
            OSError: If a system error occurred.
        """
        return self.recvuntil(
            delim=self.newlines,
            blocksize=blocksize,
            regex=None,
            timeout=timeout,
            drop=drop,
            consume=consume
        )

    def recvregex(self,
                  regex: RegexDelimiterT,
                  blocksize: int = 4096,
                  timeout: int | float = -1,
                  consume: bool = True) -> re.Match:
        """Block until any of the regex patterns matches and return the match object.

        The search is performed against the internal buffer. If no match is found,
        more data is read from the underlying endpoint in chunks of ``blocksize``
        until a match is found or EOF occurs.

        Args:
            regex: A single pattern or a list of patterns (bytes/str/compiled).
            blocksize: Number of bytes to request per low-level read.
            timeout: Timeout for each low-level read operation.
            consume: If True, bytes up to the end of the match are removed
                     from the internal buffer.

        Returns:
            re.Match: The first match found (ties broken by the earliest match end).

        Raises:
            EOFError: If the connection is closed before a match is found.
            ValueError: If ``blocksize`` is negative.
            TubeTimeout: If the operation timed out.
            OSError: If a system error occurred.
        """
        patterns = self._normalize_patterns(regex)
        if len(patterns) == 0:
            raise ValueError("No pattern is provided.")

        def _best_match(buf: bytes) -> re.Match | None:
            best_m = None
            best_end = -1
            for pat in patterns:
                m = pat.search(buf)
                if m:
                    e = m.end()
                    if best_end == -1 or e < best_end:
                        best_end = e
                        best_m = m
            return best_m

        out, self._buffer = bytearray(self._buffer), b''
        while True:
            m = _best_match(out)
            if m is not None:
                if consume:
                    self._buffer = out[m.end():]
                else:
                    self._buffer = out
                return m

            # Need more data
            with self.timeout(timeout):
                try:
                    chunk = self.recv(blocksize)
                except TubeTimeout as e:
                    raise TubeTimeout(str(e), buffered=out) from None

            out += chunk

    def recvuntil(self,
                  delim: DelimiterT | None = None,
                  blocksize: int = 4096,
                  regex: RegexDelimiterT | None = None,
                  timeout: int | float = -1,
                  drop: bool = False,
                  consume: bool = True) -> bytes:
        """Receive until a delimiter or regex match is found.

        Exactly one of ``delim`` or ``regex`` must be provided.

        Args:
            delim: Delimiter(s) to wait for. A single ``bytes``/``str`` or a list of such
                values. If a list is given, the method stops at the **earliest** occurrence
                of **any** delimiter.
            blocksize: Number of bytes to request per low-level read.
            regex: A single regex pattern or a list of patterns. Patterns may be ``bytes``,
                ``str``, or compiled ``re.Pattern``.
                The method stops at the **earliest** match among all patterns.
            timeout: Timeout for each low-level read operation.
            drop: If True, exclude the newline delimiter from the returned bytes.
            consume: If True, remove the delimiter from the internal buffer.

        Returns:
            bytes: Data up to (and optionally including) the match. When ``regex`` is used,
                this method still returns **bytes**, not a match object.

        Raises:
            EOFError: If the connection is closed before a delimiter or pattern is found.
            ValueError: If both or neither of ``delim`` and ``regex`` are provided,
                        or if ``blocksize`` is negative.
            TubeTimeout: If the operation timed out.
            OSError: If a system error occurred.
        """
        use_delim = delim is not None
        use_regex = regex is not None
        if use_delim == use_regex:
            raise ValueError("Specify exactly one of `delim` or `regex`.")

        if use_regex:
            # Regex path
            m = self.recvregex(regex, blocksize, timeout=timeout, consume=False)
            with self._mutex:
                start, end = m.span()
                before = self._buffer[:start]
                matched = self._buffer[start:end]
                ret = before if drop else before + matched
                if consume:
                    self._buffer = self._buffer[end:]
            return ret

        # Delimiter path
        assert delim is not None
        delims = self._normalize_delims(delim)

        def _search(buf: bytes) -> tuple[int, int] | None:
            best = None
            for d in delims:
                idx = buf.find(d)
                if idx != -1:
                    end = idx + len(d)
                    if best is None or end < best[1]:
                        best = (idx, end)
            return best

        out, self._buffer = bytearray(self._buffer), b''
        while True:
            m = _search(out)
            if m is not None:
                start, end = m
                before = out[:start]
                matched = out[start:end]
                ret = before if drop else before + matched
                if consume:
                    self._buffer = out[end:]
                else:
                    self._buffer = out
                return bytes(ret)

            # Not found yet: read more
            try:
                chunk = self.recv(blocksize, timeout=timeout)
            except TubeTimeout as e:
                raise TubeTimeout(str(e), buffered=out) from None

            if not chunk:
                raise EOFError("stream ended before delimiter/regex was found")
            out += chunk

    def after(self,
              delim: DelimiterT | None = None,
              blocksize: int = 4096,
              regex: RegexDelimiterT | None = None,
              timeout: int | float = -1) -> 'Tube':
        """Wait for a delimiter (or regex) and then return `self`.

        Useful for chained calls like:
            ```
            tube.after(b'Name: ').sendline(name)
            leak = tube.after(regex=r'Hello, .{32}').recvline()
            ```

        Args:
            delim: Delimiter(s) to wait for. A single ``bytes``/``str`` or a list of such
                values. If a list is given, the method stops at the **earliest** occurrence
                of **any** delimiter.
            blocksize: Number of bytes to request per low-level read.
            regex: A single regex pattern or a list of patterns. Patterns may be ``bytes``,
                ``str``, or compiled ``re.Pattern``.
                The method stops at the **earliest** match among all patterns.
            timeout: Timeout for each low-level read operation.

        Returns:
            Tube: The current tube instance.

        Raises:
            EOFError: If the connection is closed before a delimiter or pattern is found.
            ValueError: If both or neither of ``delim`` and ``regex`` are provided,
                        or if ``blocksize`` is negative.
            TubeTimeout: If the operation timed out.
            OSError: If a system error occurred.
        """
        self.recvuntil(delim, blocksize, regex, timeout)
        return self

    # --- Send methods -----------------------------------------------------

    def send(self,
             data: str | bytes) -> int:
        """Send a single chunk of data

        This is a thin wrapper that issues **one** low-level write. It may
        send fewer bytes than provided, depending on the underlying endpoint.

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually written.

        Raises:
            BrokenPipeError: If the send-side has been closed by the peer.
            OSError: If a system error occurred.
        """
        if self._is_alive and not self._is_alive_impl():
            # First time detection of dead tube
            self._is_alive = False
            self._log_warning(f"Connection is closed: {str(self)}")

        data = str2bytes(data)
        if not data:
            return 0

        n = self._send_impl(data)
        self._trace_outcoming(data[:n])
        return n

    def sendall(self,
                data: str | bytes) -> int:
        """Send all bytes, blocking until everything is written (or an error occurs).

        Args:
            data: Data to send.

        Returns:
            int: Total number of bytes written (== len(data) on success).

        Raises:
            BrokenPipeError: If the send-side has been closed by the peer.
            OSError: If a system error occurred.
        """
        data = str2bytes(data)
        if not data:
            return 0

        total = 0
        view = memoryview(data)
        while total < len(view):
            n_written = self.send(view[total:])
            assert n_written >= 0, "BUG: `send` unexpectedly returned negative value"
            total += n_written
        return total

    def sendline(self,
                 data: AtomicSendT | list[AtomicSendT]) -> int:
        """Send data followed by the current newline delimiter.

        The first configured newline sequence (``self.newline[0]``) is used. If none
        is configured, ``b'\\n'`` is assumed.

        Args:
            data: String, bytes, int, float, or a list of such values.
                  Integer and float values will be converted to strings.
                  If a list is provided, each element will be sent followed by the newline.

        Returns:
            int: Total number of bytes written (payload + newline).

        Raises:
            BrokenPipeError: If the send-side has been closed by the peer.
            OSError: If a system error occurred.
        """
        if isinstance(data, list):
            total = 0
            for item in data:
                total += self.sendline(item)
            return total

        if isinstance(data, (int, float)):
            data = str(data)

        data = str2bytes(data)
        return self.sendall(data + self.newline)

    def sendkey(self):
        pass

    # --- Buffering operations ---------------------------------------------

    def peek(self, size: int = -1, blocksize: int = 4096, timeout: int | float = -1) -> bytes:
        """Return exactly ``size`` bytes from the internal buffer **without consuming** them.

        Args:
            size: The number of bytes to return. If ``size < 0``, return the entire buffer.

        Returns:
            bytes
        """
        if size < 0:
            return self._buffer

        out = self.recvall(size, blocksize, timeout)
        self.unget(out)
        return out

    def unget(self, data: str | bytes) -> None:
        """Push ``data`` back to the **front** of the internal buffer.

        The next receive operation will return these bytes first.

        Args:
            data: Bytes to be re-inserted at the start of the buffer.
        """
        if isinstance(data, str):
            data = str2bytes(data)
        with self._mutex:
            self._buffer = bytes(data) + self._buffer

    # --- Closing / lifecycle ----------------------------------------------

    def close(self):
        """Close the tube and release any resources.
        """
        if self._is_alive:
            self._is_alive = False
            self._log_info(f"Connection {str(self)} closed")
            self._pcap.close()
        with self._mutex:
            self._close_impl()

    def close_recv(self):
        """Close the receive end of the tube.
        """
        with self._mutex:
            self._close_recv_impl()

    def close_send(self):
        """Close the send end of the tube.
        """
        self._close_send_impl()
        self._pcap.close_send()

    # --- Interactive session ----------------------------------------------

    def interactive(self,
                    prompt: str | None = None,
                    use_tty: bool = False,
                    is_raw: bool = False,
                    encoding: str = "utf-8",
                    blocksize: int = 4096,
                    *,
                    readline: typing.Callable[[], str] | None = None,
                    oninterrupt: typing.Callable[[], bool] | None = None,
                    onexit: typing.Callable[[], None] | None = None,
                    ansi_on_windows: bool = True):
        """Run an interactive session with the remote endpoint.

        Two-thread model:
            - RX thread: continuously receives bytes and prints them to stdout.
            - TX thread: prompts and reads user input, then sends it to the peer.

        Output formatting:
            - If ``is_raw`` is True, received bytes are written to ``stdout.buffer`` as-is.
            - If ``is_raw`` is False, bytes are decoded with ``encoding`` and undecodable
              bytes are rendered as ``\\xNN`` using ``errors='backslashreplace'``.

        Input modes:
            - Line mode (default): each line is sent with the tube's newline sequence
              (via ``sendline``). The line source is ``readline()`` if provided;
              otherwise a built-in line reader is used.
            - Key passthrough (``use_tty=True``): character-at-a-time mode.
              On POSIX, the local terminal is switched to raw mode so that arrow keys
              and ESC sequences are passed unchanged. On Windows, raw keystrokes are
              read via ``msvcrt``; if ``ansi_on_windows`` is True, common special keys
              (arrows) are translated to ANSI escape sequences (e.g. Up => ``\\x1b[A``).

        Session control:
            - ``oninterrupt`` is called when the user hits Ctrl-C in line mode.
              If it returns True, the session continues; otherwise the session ends.
            - In key passthrough mode, Ctrl-C is sent to the peer as ``\\x03``.
              Use ``escape_key`` (default: Ctrl-]) to locally end the session.
            - ``onexit`` is called once both threads finish and just before returning.

        This method blocks until the session ends and **swallows network I/O errors**
        inside worker threads (they terminate the session instead of raising here).

        Args:
            prompt: Prompt string shown in line mode.
            use_tty: Enable character-at-a-time mode for TUI/curses programs.
            is_raw: If True, print incoming bytes as-is without decoding.
                    Always treated as True if ``use_tty`` is set to True.
            encoding: Text encoding used when ``is_raw`` is False (default: UTF-8).
            readline: Optional callable that returns a single input line (without EOL).
            oninterrupt: Callback invoked on KeyboardInterrupt in line mode.
                         Return True to continue, False/None to end the session.
            onexit: Callback invoked when the interactive session ends.
            ansi_on_windows: Windows only—translate arrow keys to ANSI if True.

        Raises:
            ValueError: If ``use_tty`` is requested but stdin is not a TTY.
            RuntimeError: If platform lacks required TTY support in passthrough mode.
        """
        rx_timeout = 0.01
        tx_timeout = 0.01
        stop = threading.Event()
        io_lock = threading.Lock()

        if prompt is None:
            prompt = self._prompt

        if use_tty:
            is_raw = True

        def rx_worker():
            while not stop.is_set():
                try:
                    data = self.recv(blocksize, timeout=rx_timeout)
                    if not data:
                        stop.set()
                        break

                    with io_lock:
                        if is_raw:
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                        else:
                            text = data.decode(encoding, errors='backslashreplace')
                            sys.stdout.write(text)
                            sys.stdout.flush()

                except TubeTimeout:
                    continue

                except (EOFError, OSError):
                    # Peer closed
                    stop.set()
                    break

        def tx_line_reader() -> str | None:
            if readline is not None:
                try:
                    return readline()
                except KeyboardInterrupt:
                    # When interrupt is raised from custom readline
                    return None

            if _is_posix():
                while not stop.is_set():
                    r, [], [] = select.select([sys.stdin], [], [], tx_timeout)
                    if r:
                        break

            line = sys.stdin.readline()
            if line == '':
                return None
            return line

        def tx_worker_line_mode():
            while not stop.is_set():
                if prompt:
                    time.sleep(tx_timeout) # TODO: Delay prompt for better UX
                    with io_lock:
                        sys.stdout.write(f"{Color.BOLD}{Color.BLUE}{prompt}{Color.END}")
                        sys.stdout.flush()
                try:
                    line = tx_line_reader()
                except KeyboardInterrupt:
                    # Ctrl-C: let the caller decide
                    if oninterrupt is not None:
                        cont = bool(oninterrupt())
                    else:
                        cont = False

                    if cont:
                        with io_lock:
                            sys.stdout.write("\n")
                            sys.stdout.flush()
                        continue

                    stop.set()
                    break

                if line is None:
                    # Stdin closed (Ctrl-D) or stop signaled
                    stop.set()
                    break

                try:
                    self.send(str2bytes(line))
                except (BrokenPipeError, OSError) as e:
                    stop.set()
                    self._logger.error("Connection closed: %s", e)
                    break

        def tx_worker_key_mode():
            # Character-at-a-time; POSIX: raw TTY; Windows: msvcrt
            if _is_posix():
                if not _is_tty_stdin():
                    raise ValueError("`use_tty` requires a TTY on stdin")
                import termios, tty
                fd = sys.stdin.fileno()
                old_attrs = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd, termios.TCSANOW)
                    while not stop.is_set():
                        r, _, _ = select.select([fd], [], [])
                        if stop.is_set():
                            break
                        if not r:
                            continue
                        data = os.read(fd, 4096)
                        if not data:
                            stop.set()
                            break

                        try:
                            self.sendall(data)
                        except (BrokenPipeError, OSError) as e:
                            stop.set()
                            self._logger.error("Connection closed: %s", e)
                            break
                finally:
                    # Restore terminal attributes
                    with contextlib.suppress(Exception):
                        termios.tcsetattr(fd, termios.TCSANOW, old_attrs)

            else:
                # Windows
                try:
                    import msvcrt
                except Exception as e:
                    raise RuntimeError("key_passthrough requires msvcrt on Windows") from e

                def _win_key_to_ansi() -> bytes | None:
                    """Read a key; convert arrows to ANSI if requested."""
                    ch = msvcrt.getwch()  # returns str
                    if ch == '\x00' or ch == '\xe0':
                        # special key prefix
                        code = msvcrt.getwch()
                        if not ansi_on_windows:
                            # return None to ignore special keys or encode direct?
                            return b""
                        m = {
                            'H': '\x1b[A',  # up
                            'P': '\x1b[B',  # down
                            'K': '\x1b[D',  # left
                            'M': '\x1b[C',  # right
                        }.get(code)
                        return m.encode('ascii') if m else b""
                    else:
                        return ch.encode('utf-8', errors='ignore')

                while not stop.is_set():
                    if not msvcrt.kbhit():
                        time.sleep(rx_timeout)
                        continue
                    b = _win_key_to_ansi()
                    if b is None:
                        continue
                    if b == b"":
                        continue

                    try:
                        self.sendall(b)
                    except (BrokenPipeError, OSError):
                        stop.set()
                        break

        rx = threading.Thread(target=rx_worker, name='tube-rx', daemon=True)
        if use_tty:
            tx = threading.Thread(target=tx_worker_key_mode, name='tube-tx', daemon=True)
        else:
            tx = threading.Thread(target=tx_worker_line_mode, name='tube-tx', daemon=True)

        rx.start()
        tx.start()

        try:
            while tx.is_alive() or rx.is_alive():
                if not tx.is_alive() or not rx.is_alive():
                    stop.set()
                time.sleep(rx_timeout)
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            tx.join(timeout=0.1)
            rx.join(timeout=0.1)
            if onexit:
                onexit()

    def sh(self, *args, **kwargs):
        self.interactive(*args, **kwargs)

    # --- Timeout ----------------------------------------------------------

    @contextlib.contextmanager
    def timeout(self, timeout: int | float):
        """Temporarily set an I/O timeout for the enclosed operations.

        The previous timeout value is restored after the context exits.

        Args:
            timeout: The timeout value in seconds.
                     If ``timeout`` is negative, the timeout is temporarily disabled.

        Examples:
            ```
            with tube.timeout(5):
                line = tube.recvline()
            ```
        """
        old_timeout = self._gettimeout_impl()
        try:
            self._settimeout_impl(timeout)
            yield
        finally:
            self._settimeout_impl(old_timeout)

    # --- Backward compatibility -------------------------------------------

    def recvlineafter(self,
                      delim: DelimiterT,
                      blocksize: int = 4096,
                      regex: RegexDelimiterT | None = None,
                      timeout: int | float = -1,
                      drop: bool = True,
                      consume: bool = True) -> bytes:
        """Wait for a delimiter (or regex), then read a line.

        Note:
            This method is deprecated.
            Use `after(delim, blocksize, regex, timeout).recvline(...)` instead.
        """
        return self.after(delim, blocksize, regex, timeout) \
            .recvline(blocksize, timeout, drop, consume)

    def sendlineafter(self,
                      delim: DelimiterT,
                      data: str | bytes,
                      blocksize: int = 4096,
                      regex: RegexDelimiterT | None = None,
                      timeout: int | float = -1) -> int:
        """Wait for a delimiter (or regex), then send a line.

        Note:
            This method is deprecated.
            Use `after(delim, blocksize, regex, timeout).sendline(...)` instead.
        """
        return self.after(delim, blocksize, regex, timeout) \
            .sendline(data)

    def shutdown(self, target: typing.Literal['send', 'recv']):
        """Shut down a specific connection.

        Args:
            target (str): Connection to close (`send` or `recv`)

        Examples:
           The following code shuts down input of remote.
           ```
           tube.shutdown("send")
           data = tube.recv() # OK
           tube.send(b"data") # NG
           ```

           The following code shuts down output of remote.
           ```
           tube.shutdown("recv")
           tube.send(b"data") # OK
           data = tube.recv() # NG
           ```
        """
        if target.lower() in ['write', 'send', 'stdin']:
            self.close_send()
        elif target.lower() in ['read', 'recv', 'stdout', 'stderr']:
            self.close_recv()
        else:
            raise ValueError("`target` must either 'send' or 'recv'")

    # --- Helpers ----------------------------------------------------------

    def _normalize_delims(self, d: DelimiterT) -> list[bytes]:
        if isinstance(d, list):
            return [str2bytes(x) for x in d]
        return [str2bytes(d)]

    def _normalize_patterns(self, p: RegexDelimiterT) -> list[re.Pattern]:
        items = p if isinstance(p, list) else [p]
        compiled: list[re.Pattern] = []
        for it in items:
            if isinstance(it, re.Pattern):
                compiled.append(it)
            else:
                compiled.append(re.compile(str2bytes(it), re.DOTALL))
        return compiled

    def _trace_outcoming(self, data: bytes) -> bytes:
        if self._debug == 'hex':
            hexdump(data, prefix=f"{Color.WHITE}[send] {Color.END}")
        elif self._debug == 'plain':
            for line in data.split(self.newline):
                log  = Color.WHITE.encode() + b'[send] ' + Color.END.encode()
                log += Color.BRIGHT_CYAN.encode() + line + self.newline + Color.END.encode()
                sys.stdout.buffer.write(log)
                sys.stdout.buffer.flush()

        self._pcap.send(data)
        return data

    def _trace_incoming(self, data: bytes) -> bytes:
        if self._debug == 'hex':
            hexdump(data, prefix=f"{Color.WHITE}[recv] {Color.END}",
                    color_ascii=Color.BRIGHT_GREEN, color_nonascii=Color.GREEN)
        elif self._debug == 'plain':
            for line in data.split(self.newline):
                log  = Color.WHITE.encode() + b'[recv] ' + Color.END.encode()
                log += Color.BRIGHT_GREEN.encode() + line + self.newline + Color.END.encode()
                sys.stdout.buffer.write(log)
                sys.stdout.buffer.flush()

        self._pcap.recv(data)
        return data

    @staticmethod
    def _sanitize_filename(name: str, maxlen: int = 255) -> str:
        s = unicodedata.normalize("NFKC", name)
        s = s.replace("\x00", "")
        s = s.replace("/", "_")
        s = s.replace(os.sep, "_")

        out = []
        prev_us = False
        for ch in s:
            cat = unicodedata.category(ch)[0]
            if ch in "._-" or cat in ("L", "N"):
                out.append(ch)
                prev_us = False
            else:
                if not prev_us:
                    out.append("_")
                    prev_us = True

        base = "".join(out)
        base = re.sub(r"_+", "_", base)
        base = base.strip("._")
        if not base:
            base = "untitled"
        if base[0] == ".":
            base = "_" + base.lstrip(".")

        def fits(b: str) -> bool:
            return len(b.encode("utf-8")) <= maxlen

        while not fits(base) and len(base) > 1:
            base = base[:-1]
        if not fits(base):
            base = ""

        if not base:
            base = "untitled"
            while not fits(base) and len(base) > 1:
                base = base[:-1]

        return base

    # --- Abstracts --------------------------------------------------------

    @property
    @abc.abstractmethod
    def _logname_impl(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def _recv_impl(self, blocksize: int) -> bytes:
        """Low-level receive. Must be implemented by subclasses.

        Args:
            blocksize: The maximum number of bytes to read.

        Returns:
            bytes: The received data.

        Raises:
            EOFError: The process has closed its output stream.
            TimeoutError: The operation timed out.
            OSError: System error.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _send_impl(self, data: bytes) -> int:
        """Low-level send. Must be implemented by subclasses.
        
        Args:
            data: Data to send.

        Returns:
            int: The number of bytes sent.

        Raises:
            BrokenPipeError: The process has closed its input stream.
            TimeoutError: The operation timed out.
            OSError: System error.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _close_impl(self):
        """Low-level close. Must be implemented by subclasses.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _close_recv_impl(self):
        """Low-level close receive. Must be implemented by subclasses.

        Closes the receive channel if possible.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _close_send_impl(self):
        """Low-level close send. Must be implemented by subclasses.

        Closes the send channel if possible.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _settimeout_impl(self, timeout: float):
        """Low-level timeout setter. Must be implemented by subclasses.

        Args:
            timeout: The timeout value to set.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _gettimeout_impl(self) -> float:
        """Low-level timeout getter. Must be implemented by subclasses.

        Returns:
            The current timeout value.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _is_alive_impl(self) -> bool:
        """Low-level liveness check. Must be implemented by subclasses.

        Implementation of this method should return True
        if it cannot determine the liveness of the connection.

        Returns:
            bool: True if the connection is alive, False otherwise.
        """
        raise NotImplementedError

class TubeTimeout(TimeoutError):
    """Timeout with captured partial data.

    Attributes:
        buffered (bytes): Bytes obtained until timeout.

    Note:
        - This exception subclasses `TimeoutError`, so existing `except TimeoutError`
          handlers will still work. Prefer catching `TubeTimeout` when you need data.
    """
    def __init__(self, message: str, *, buffered: bytes = b''):
        super().__init__(message)
        self.buffered = bytes(buffered)

    def __bytes__(self) -> bytes:
        return self.buffered

__all__ = ['Tube', 'TubeTimeout']
