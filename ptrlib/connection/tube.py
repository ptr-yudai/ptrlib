"""This package provides Tube class.
"""
import abc
import os
import re
import select
import sys
import threading
from logging import getLogger
from typing import Callable, List, Literal, Match, Optional, Union, Pattern, TypeVar
from ptrlib.binary.encoding import \
    bytes2str, str2bytes, bytes2hex, bytes2utf8, \
    hexdump, AnsiParser, AnsiInstruction
from ptrlib.console.color import Color
from ptrlib.types import PtrlibIntLikeT

_is_windows = os.name == 'nt'

logger = getLogger(__name__)


def tube_is_open(method):
    """Ensure that connection is not *explicitly* closed
    """
    def decorator(self, *args, **kwargs):
        assert isinstance(self, Tube), "Invalid usage of decorator"
        if self.is_closed:
            raise BrokenPipeError("Connection has already been closed by `close`")
        return method(self, *args, **kwargs)
    return decorator

def tube_is_send_open(method):
    """Ensure that sender connection is not explicitly closed
    """
    def decorator(self, *args, **kwargs):
        assert isinstance(self, Tube), "Invalid usage of decorator"
        if self.is_send_closed:
            raise BrokenPipeError("Connection has already been closed by `shutdown`")
        return method(self, *args, **kwargs)
    return decorator

def tube_is_recv_open(method):
    """Ensure that receiver connection is not explicitly closed
    """
    def decorator(self, *args, **kwargs):
        assert isinstance(self, Tube), "Invalid usage of decorator"
        if self.is_recv_closed:
            raise BrokenPipeError("Connection has already been closed by `shutdown`")
        return method(self, *args, **kwargs)
    return decorator



TubeType = TypeVar('TubeType', bound='Tube')
AtomicSendT = Union[PtrlibIntLikeT, float, str, bytes]
AtomicRecvT = Union[str, bytes]

class Tube(metaclass=abc.ABCMeta):
    """Abstract class for streaming data

    A child class must implement the following methods:

      - "_settimeout_impl"
      - "_recv_impl"
      - "_send_impl"
      - "_close_impl"
      - "_is_alive_impl
      - "_shutdown_recv_impl"
      - "_shutdown_send_impl"
    """
    _POLL_TIMEOUT = 0.1

    def __new__(cls, *args, **kwargs):
        cls._settimeout_impl = tube_is_open(cls._settimeout_impl)
        cls._recv_impl = tube_is_recv_open(tube_is_open(cls._recv_impl))
        cls._send_impl = tube_is_send_open(tube_is_open(cls._send_impl))
        cls._close_impl = tube_is_open(cls._close_impl)
        cls._is_alive_impl = tube_is_open(cls._is_alive_impl)
        cls._shutdown_recv_impl = tube_is_recv_open(cls._shutdown_recv_impl)
        cls._shutdown_send_impl = tube_is_send_open(cls._shutdown_send_impl)
        return super().__new__(cls)

    #
    # Constructor
    #
    def __init__(self,
                 timeout: Union[int, float]=0):
        """Base constructor

        Args:
            timeout (float): Default timeout in second.
        """
        self._buffer = b''
        self._debug = False
        self._hexdump = True

        self._is_closed = False
        self._is_send_closed = False
        self._is_recv_closed = False

        self._newline = b'\n'
        self._default_timeout = timeout
        self.settimeout()

    #
    # Properties
    #
    @property
    def debug(self):
        """Debug mode.

        Every packet is printed on calling recv and send methods if the debug mode is enabled.

        Values:
            - `False`: Disable debug mode.
            - `True`: Enable debug mode.
            - `"plain"`: Enable debug mode and change print format to plaintext mode.
            - `"hex"`: Enable debug mode and change print format to hexdump mode.

        Examples:
            ```
            sock = Socket("...")
            sock.debug = True
            sock.debug = 'plain'
            sock.debug = 'hex'
            ```
        """
        return self._debug

    @debug.setter
    def debug(self, is_debug: Union[bool, Literal['plain', 'hex']]):
        if isinstance(is_debug, bool):
            self._debug = is_debug
        elif is_debug == 'plain':
            self._debug = True
            self._hexdump = False
        elif is_debug == 'hex':
            self._debug = True
            self._hexdump = True
        else:
            raise ValueError('`debug` can be either bool, "plain", or "hex"')

    @property
    def is_closed(self):
        """Get if this tube is explicitly closed.
        """
        return self._is_closed

    @property
    def is_send_closed(self):
        """Get if the tube for sending data is explicitly closed.
        """
        return self._is_send_closed

    @property
    def is_recv_closed(self):
        """Get if the tube for receiving data is explicitly closed.
        """
        return self._is_recv_closed
    
    @property
    def newline(self) -> bytes:
        """Get the current definition of a newline.
        """
        return self._newline
    
    @newline.setter
    def newline(self, line: bytes):
        assert isinstance(line, (bytes, bytearray)), f"Newline must be bytes, not {type(line)}"
        self._newline = line

    #
    # Methods
    #
    def settimeout(self, timeout: Optional[Union[float, PtrlibIntLikeT]]=None):
        """Set timeout
        
        Args:
            timeout (float): Timeout in second

        Note:
            Set timeout to None in order to set the default timeout)

        Examples:
            ```
            p = Socket("0.0.0.0", 1337, timeout=3)
            # ...
            p.settimeout(5) # Timeout is set to 5
            # ...
            p.settimeout()  # Timeout is set to 3
            ```
        """
        if timeout is None:
            self._settimeout_impl(self._default_timeout)
        elif not isinstance(timeout, float):
            self._settimeout_impl(int(timeout))
        else:
            self._settimeout_impl(timeout)

    def recv(self,
             size: PtrlibIntLikeT=4096,
             timeout: Optional[Union[PtrlibIntLikeT, float]]=None) -> bytes:
        """Receive data with buffering

        Receive raw data of at most `size` bytes.

        Args:
            size   : Size to receive (Use `recvonce` to read exactly `size` bytes)
            timeout: Timeout in second

        Returns:
            bytes: Received data

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error

        Examples:
            ```
            tube.recv(4)
            try:
                tube.recv(timeout=3.14)
            except TimeoutError:
                pass
            ```
        """
        if size is not None:
            size = int(size)
            assert size >= 0, "`size` must be a positive integer"

        # NOTE: We always return buffer if it's not empty
        # This is because we do not know how many bytes we can read.
        if len(self._buffer):
            data, self._buffer = self._buffer[:size], self._buffer[size:]
            return data

        if timeout is not None:
            self.settimeout(timeout)

        try:
            data = self._recv_impl(size - len(self._buffer))
            if self._debug and len(data) > 0:
                logger.info("Received %s (%d}) bytes:", hex(len(data)), len(data))
                if self._hexdump:
                    hexdump(data, prefix="    " + Color.CYAN, postfix=Color.END)
                else:
                    sys.stdout.write(f'{Color.BOLD}<< {Color.CYAN}')
                    utf8str, leftover, marker = bytes2utf8(data)
                    for c, t in zip(utf8str, marker):
                        if t:
                            if 0x7f <= ord(c) < 0x100 or c == 0:
                                sys.stdout.write(f'{Color.RED}\\x{ord(c):02x}{Color.CYAN}')
                            elif ord(c) == 0x0a:
                                sys.stdout.write(f'{c}{Color.END}{Color.BOLD}<< {Color.CYAN}')
                            else:
                                sys.stdout.write(c)
                        else:
                            sys.stdout.write(f'{Color.RED}\\x{ord(c):02x}{Color.CYAN}')
                    sys.stdout.write(bytes2str(leftover))
                    sys.stdout.write(f'{Color.END}\n')

            self._buffer += data

        except TimeoutError as err:
            data = self._buffer + err.args[1]
            self._buffer = b''
            raise TimeoutError("Timeout (recv)", data) from err

        finally:
            if timeout is not None:
                # Reset timeout to default value
                self.settimeout()

        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def recvonce(self,
                 size: int,
                 timeout: Optional[Union[int, float]]=None) -> bytes:
        """Receive raw data of exact size with buffering

        Receive raw data of exactly `size` bytes.

        Args:
            size   : Data size to receive
            timeout: Timeout in second

        Returns:
            bytes: Received data
        """
        data = b''

        while len(data) < size:
            try:
                data += self.recv(size - len(data), timeout)
            except TimeoutError as err:
                raise TimeoutError("Timeout (recvonce)", data + err.args[1]) from err

        if len(data) > size:
            self.unget(data[size:])
        return data[:size]

    def recvuntil(self,
                  delim: Union[AtomicRecvT, List[AtomicRecvT]],
                  size: int=4096,
                  timeout: Optional[Union[int, float]]=None,
                  drop: bool=False,
                  lookahead: bool=False) -> bytes:
        """Receive raw data until `delim` comes

        Args:
            delim    : The delimiter bytes
            size     : The data size to receive at once
            timeout  : Timeout in second
            drop     : Discard delimiter or not
            lookahead: Unget delimiter to buffer or not

        Returns:
            bytes: Received data

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error

        Examples:
            ```
            echo.sendline("abc123def")
            echo.recvuntil("123") # abc123

            echo.sendline("abc123def")
            echo.recvuntil("123", drop=True) # abc

            echo.sendline("abc123def")
            echo.recvuntil("123", lookahead=True) # abc123
            echo.recvonce(6)                      # 123def
            ```
        """
        assert isinstance(delim, (str, bytes, bytearray, list)), \
            "`delim` must be either str, bytes, or list"

        # Preprocess
        delim_list: List[bytes] = []
        if isinstance(delim, list):
            for i, d in enumerate(delim):
                assert isinstance(d, (str, bytes, bytearray)), \
                    f"`delim[{i}]` must be either str or bytes"
                delim_list.append(str2bytes(delim[i]))
        else:
            delim_list.append(str2bytes(delim))

        if any(map(lambda d: len(d) == 0, delim_list)):
            return b'' # Empty delimiter

        # Iterate until we find one of the delimiters
        found_delim = None
        prev_len = 0
        data = b''
        while True:
            try:
                data += self.recv(size, timeout)
            except TimeoutError as err:
                raise TimeoutError("Timeout (recvuntil)", data + err.args[1]) from err
            except Exception as err:
                err.args = (err.args[0], data)
                raise err from None

            for d in delim_list:
                if d in data[max(0, prev_len-len(d)):]:
                    found_delim = d
                    break
            if found_delim is not None:
                break

            prev_len = len(data)

        i = data.find(found_delim)
        j = i + len(found_delim)
        if not drop:
            i = j

        ret, data = data[:i], data[j:]
        self.unget(data)
        if lookahead:
            self.unget(found_delim)

        return ret

    def recvline(self,
                 size: int=4096,
                 timeout: Optional[Union[int, float]]=None,
                 drop: bool=True,
                 lookahead: bool=False) -> bytes:
        """Receive a line of data

        Args:
            size     : The data size to receive at once
            timeout  : Timeout (in second)
            drop     : Discard trailing newlines or not
            lookahead: Unget trailing newline to buffer or not

        Returns:
            bytes: Received data
        """
        try:
            line = self.recvuntil(self._newline, size, timeout, lookahead=lookahead)
        except TimeoutError as err:
            raise TimeoutError("Timeout (recvline)", err.args[1]) from err

        return line.rstrip() if drop else line

    def recvlineafter(self,
                      delim: Union[AtomicRecvT, List[AtomicRecvT]],
                      size: int=4096,
                      timeout: Optional[Union[int, float]]=None,
                      drop: bool=True,
                      lookahead: bool=False) -> bytes:
        """Receive a line of data after receiving `delim`

        Args:
            delim    : The delimiter bytes
            size     : The data size to receive at once
            timeout  : Timeout (in second)
            drop     : Discard trailing newline or not
            lookahead: Unget trailing newline to buffer or not

        Returns:
            bytes: Received data

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error
        """
        try:
            self.recvuntil(delim, size, timeout)
        except TimeoutError as err:
            # NOTE: We do not set received value here
            raise TimeoutError("Timeout (recvlineafter)", b'') from err

        try:
            return self.recvline(size, timeout, drop, lookahead)
        except TimeoutError as err:
            raise TimeoutError("Timeout (recvlineafter)", err.args[1]) from err

    def recvregex(self,
                  regex: Union[str, bytes, Pattern[bytes]],
                  size: int=4096,
                  timeout: Optional[Union[int, float]]=None) -> Match[bytes]:
        """Receive until a pattern comes

        Receive data until a given regex pattern matches.

        Args:
            regex  : Regular expression
            size   : Size to read at once
            timeout: Timeout in second

        Returns:
            re.Match: Returns a :obj:`re.Match` object.

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error
        """
        assert isinstance(regex, (str, bytes, bytearray, re.Pattern)), \
            "`regex` must be either str, bytes, or re.Pattern"

        if isinstance(regex, str):
            regex = str2bytes(regex)
        regex = re.compile(regex)

        data = b''
        match = None
        while match is None:
            try:
                data += self.recv(size, timeout)
            except TimeoutError as err:
                raise TimeoutError("Timeout (recvregex)", data + err.args[1]) from err
            match = regex.search(data)

        self.unget(data[match.end():])
        return match

    def recvscreen(self,
                   returns: type=str,
                   stop: Optional[Callable[[AnsiInstruction], bool]]=None,
                   timeout: Union[int, float]=1.0):
        """Receive a screen

        Receive a screen drawn by ncurses (ANSI escape sequence)

        Args:
            returns: Either str or list
            stop: Function to determine when to stop emulating instructions
            timeout: Timeout until stopping recv

        Returns:
            str: Rectangle string drawing the screen
        """
        assert returns in [list, str, bytes], \
            "`returns` must be either list or str"

        def _ansi_stream(self):
            """Generator for recvscreen
            """
            while True:
                try:
                    yield self.recv(timeout=timeout)
                except TimeoutError as e:
                    self.unget(e.args[1])
                    break

        ansi = AnsiParser(_ansi_stream(self))
        scr = ansi.draw_screen(returns, stop)
        self.unget(ansi.buffer)
        return scr

    def before(self: TubeType,
              delim: Union[AtomicRecvT, List[AtomicRecvT]],
              size: int = 4096,
              timeout: Optional[Union[int, float]] = None) -> TubeType:
        """Wait until data arrives. 

        This method works in the same as `recvuntil` except that this method returns `self`
        and received data is buffered.

        Args:
            delim    : The delimiter bytes
            size     : The data size to receive at once
            timeout  : Timeout in second

        Returns:
            Tube: Self.

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error

        Examples:
            ```
            msg = tube.after("Message: ").recvline()
            tube.after("[42] ").recvregex(r"ID: (\\d+)")
            ```
        """
        raise NotImplementedError("Not implemented yet")

    def after(self: TubeType,
              delim: Union[AtomicRecvT, List[AtomicRecvT]],
              size: int = 4096,
              timeout: Optional[Union[int, float]] = None,
              lookahead: bool = False) -> TubeType:
        """Wait until data arrives.

        This method works in the same as `recvuntil` except that this method returns `self`.

        Args:
            delim    : The delimiter bytes
            size     : The data size to receive at once
            timeout  : Timeout in second
            lookahead: Unget delimiter to buffer or not

        Returns:
            Tube: Self.

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error

        Examples:
            ```
            msg = tube.after("Message: ").recvline()
            tube.after("[42] ").recvregex(r"ID: (\\d+)")
            ```
        """
        self.recvuntil(delim, size, timeout, True, lookahead)
        return self

    def send(self, data: Union[str, bytes]) -> int:
        """Send raw data

        Send as much data as possible.

        Args:
            data: Data to send

        Returns:
            int: Length of sent data

        Note:
            It is NOT ensured that all data is sent.
            Use `sendonce` to make sure the whole data is sent.

        Examples:
            ```
            tube.send("Hello")
            tube.send(b"\xde\xad\xbe\xef")
            ```
        """
        assert isinstance(data, (str, bytes, bytearray)), "`data` must be either str or bytes"
        data = str2bytes(data)

        size = self._send_impl(data)
        if self._debug:
            logger.info("Sent %s (%d) bytes:", hex(size), size)
            if self._hexdump:
                hexdump(data[:size], prefix=Color.YELLOW, postfix=Color.END)
            else:
                sys.stdout.write(f'{Color.BOLD}>> {Color.YELLOW}')
                utf8str, leftover, marker = bytes2utf8(data[:size])
                for c, t in zip(utf8str, marker):
                    if t:
                        if 0x7f <= ord(c) < 0x100 or c == 0:
                            sys.stdout.write(f'{Color.RED}\\x{ord(c):02x}{Color.YELLOW}')
                        elif ord(c) == 0x0a:
                            sys.stdout.write(f'{c}{Color.END}{Color.BOLD}>> {Color.YELLOW}')
                        else:
                            sys.stdout.write(c)
                    else:
                        sys.stdout.write(f'{Color.RED}\\x{ord(c):02x}{Color.YELLOW}')
                sys.stdout.write(bytes2str(leftover))
                sys.stdout.write(f'{Color.END}\n')


        return size

    def sendonce(self, data: Union[str, bytes]):
        """Send the whole data

        Send the whole data.
        This method will never return until it finishes sending
        the whole data, unlike `send`.

        Args:
            data: Data to send
        """
        to_send = len(data)
        while to_send > 0:
            sent = self.send(data)
            data = data[sent:]
            to_send -= sent

    def sendline(self,
                 data: Union[AtomicSendT, List[AtomicSendT]]):
        """Send a line

        Send a line of data.

        Args:
            data (bytes) : Data to send
        """
        if isinstance(data, list):
            for d in data:
                self.sendline(d)
            return
        
        if isinstance(data, (str, bytes, bytearray)):
            data = str2bytes(data)

        elif isinstance(data, float):
            data = str(data).encode()

        else:
            # Explicitly call "__int__"
            data = str(int(data)).encode()

        self.send(data + self._newline)

    def sendafter(self,
                  delim: Union[AtomicRecvT, List[AtomicRecvT]],
                  data: AtomicSendT,
                  size: int=4096,
                  timeout: Optional[Union[int, float]]=None,
                  drop: bool=False,
                  lookahead: bool=False) -> bytes:
        """Send raw data after a delimiter

        Send raw data after `delim` is received.

        Args:
            delim    : The delimiter
            data     : Data to send
            size     : Data size to receive at once
            timeout  : Timeout in second
            drop     : Discard delimiter or not
            lookahead: Unget delimiter to buffer or not

        Returns:
            bytes: Received bytes before `delim` comes.

        Examples:
            ```
            tube.sendafter("> ", p32(len(data)) + data)
            tube.sendafter("command: ", 1) # b"1" is sent
            ```
        """
        recv_data = self.recvuntil(delim, size, timeout, drop, lookahead)

        if isinstance(data, (str, bytes, bytearray)):
            data = str2bytes(data)

        elif isinstance(data, float):
            data = str(data).encode()

        else:
            # Explicitly call "__int__"
            data = str(int(data)).encode()

        self.send(data)
        return recv_data

    def sendlineafter(self,
                      delim: Union[AtomicRecvT, List[AtomicRecvT]],
                      data: AtomicSendT,
                      size: int=4096,
                      timeout: Optional[Union[int, float]]=None,
                      drop: bool=False,
                      lookahead: bool=False) -> bytes:
        """Send raw data after a delimiter

        Send raw data with newline after `delim` is received.

        Args:
            delim (bytes): The delimiter
            data (bytes) : Data to send
            timeout (int): Timeout (in second)

        Returns:
            bytes: Received bytes before `delim` comes.
        """
        recv_data = self.recvuntil(delim, size, timeout, drop, lookahead)
        self.sendline(data)

        return recv_data

    def sendctrl(self, name: str):
        """Send control key

        Send control key given its name

        Args:
            name: Name of the control key to send
        """
        if name.lower() in ['w', 'up']:
            self.send(b'\x1bOA')
        elif name.lower() in ['s', 'down']:
            self.send(b'\x1bOB')
        elif name.lower() in ['a', 'left']:
            self.send(b'\x1bOD')
        elif name.lower() in ['d', 'right']:
            self.send(b'\x1bOC')
        elif name.lower() in ['esc', 'escape']:
            self.send(b'\x1b')
        elif name.lower() in ['bk', 'backspace']:
            self.send(b'\x08')
        elif name.lower() in ['del', 'delete']:
            self.send(b'\x7f')
        else:
            raise ValueError(f"Invalid control key name: {name}")

    def sh(self,
           prompt: str="[ptrlib]$ ",
           raw: bool=False):
        """Alias for interactive

        Args:
            prompt: Prompt string to show on input
            raw   : Escape non-printable characters or not
        """
        self.interactive(prompt, raw)

    def interactive(self,
                    prompt: str="[ptrlib]$ ",
                    raw: bool=False):
        """Interactive mode

        Args:
            prompt: Prompt string to show on input
            raw   : Escape non-printable characters or not
        """
        prompt = f"{Color.BOLD}{Color.BLUE}{prompt}{Color.END}"

        def pretty_print_hex(c: str):
            sys.stdout.write(f'{Color.RED}\\x{ord(c):02x}{Color.END}')

        def pretty_print(data: bytes, prev: bytes=b''):
            """Print data in a human-friendly way
            """
            leftover = b''

            if raw:
                sys.stdout.write(bytes2str(data))

            else:
                utf8str, leftover, marker = bytes2utf8(data)
                if len(utf8str) == 0 and prev == leftover:
                    utf8str = f'{Color.RED}{bytes2hex(leftover)}{Color.END}'
                    leftover = b''

                for c, t in zip(utf8str, marker):
                    if t:
                        if 0x7f <= ord(c) < 0x100:
                            pretty_print_hex(c)
                        elif ord(c) in [0x00]:
                            pretty_print_hex(c)
                        else:
                            sys.stdout.write(c)
                    else:
                        pretty_print_hex(c)

            sys.stdout.flush()
            return leftover

        def thread_recv():
            """Receive data from tube and print to stdout
            """
            nonlocal stop_event
            leftover = b''
            while self.is_alive() and not stop_event.is_set():
                try:
                    data = self.recv(timeout=self._POLL_TIMEOUT)
                    leftover = pretty_print(data, leftover)

                    if not self.is_alive():
                        logger.warning("Connection closed by %s", str(self))

                except TimeoutError:
                    pass # NOTE: We can ignore args since recv will never buffer
                except BrokenPipeError as e:
                    logger.warning(e)
                    break
                except (EOFError, ConnectionAbortedError, ConnectionResetError) as e:
                    logger.warning("Connection closed by %s", str(self))
                    break

        def thread_send():
            """Read user input and send it to tube
            """
            import time
            nonlocal stop_event
            while self.is_alive() and not stop_event.is_set():
                sys.stdout.write(prompt)
                sys.stdout.flush()
                try:
                    if not _is_windows:
                        # NOTE: Wait for data since sys.stdin.read blocks
                        #       even if stdin is closed by keyboard interrupt
                        while self.is_alive() and not stop_event.is_set():
                            r, [], [] = select.select(
                                [sys.stdin], [], [], self._POLL_TIMEOUT
                            )
                            if r:
                                break

                    if self.is_alive() and not stop_event.is_set():
                        self.send(sys.stdin.readline())
                except (ConnectionResetError, ConnectionAbortedError, OSError, ValueError):
                    break

        stop_event = threading.Event()
        th_recv = threading.Thread(target=thread_recv)
        th_send = threading.Thread(target=thread_send)
        th_recv.start()
        th_send.start()
        try:
            th_recv.join()
            th_send.join()
        except KeyboardInterrupt:
            logger.warning("Intterupted by user")
            stop_event.set()
            th_recv.join()
            th_send.join()

    def close(self):
        """Close this connection

        Note:
            This method can only be called once.
        """
        self._close_impl()
        self._is_closed = True

    def unget(self, data: Union[str, bytes]):
        """Unshift data to buffer

        Args:
            data: Data to revert

        Examples:
            ```
            leak = tube.recvline().rstrip(b"> ")
            tube.unget("> ")
            # ...
            tube.sendlineafter("> ", "1")
            ```
        """
        assert isinstance(data, (str, bytes)), "`data` must be either str or bytes"

        self._buffer = str2bytes(data) + self._buffer

    def is_alive(self) -> bool:
        """Check if connection is not closed

        Returns:
            bool: False if connection is closed, otherwise True

        Examples:
            ```
            while tube.is_alive():
                print(tube.recv())
            ```
        """
        if self._is_closed:
            return False
        return self._is_alive_impl()

    def shutdown(self, target: Literal['send', 'recv']):
        """Kill one connection

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
        if target in ['write', 'send', 'stdin']:
            self._shutdown_send_impl()
            self._is_send_closed = True
        elif target in ['read', 'recv', 'stdout', 'stderr']:
            self._shutdown_recv_impl()
            self._is_recv_closed = True
        else:
            raise ValueError("`target` must either 'send' or 'recv'")

    def __enter__(self):
        return self

    def __exit__(self, _e_type, _e_value, _traceback):
        if not self._is_closed:
            self.close()

    def __str__(self) -> str:
        return "<unknown tube>"

    def __del__(self):
        if hasattr(self, '_init_done') and not self._is_closed:
            self.close()

    #
    # Abstract methods
    #
    @abc.abstractmethod
    def _settimeout_impl(self, timeout: Union[int, float]):
        """Abstract method for `settimeout`

        Set timeout for receive and send.

        Args:
            timeout: Timeout in second
        """

    @abc.abstractmethod
    def _recv_impl(self, size: int) -> bytes:
        """Abstract method for `recv`

        Receives at most `size` bytes from tube.
        This method must be a blocking method.
        """

    @abc.abstractmethod
    def _send_impl(self, data: bytes) -> int:
        """Abstract method for `send`

        Sends tube as much data as possible.

        Args:
            data: Data to send
        """

    @abc.abstractmethod
    def _close_impl(self):
        """Abstract method for `close`

        Close the connection.
        This method is ensured to be called only once.
        """

    @abc.abstractmethod
    def _is_alive_impl(self) -> bool:
        """Abstract method for `is_alive`

        This method must return True iff the connection is alive.
        """

    @abc.abstractmethod
    def _shutdown_recv_impl(self):
        """Kill receiver connection
        """

    @abc.abstractmethod
    def _shutdown_send_impl(self):
        """Kill sender connection
        """


__all__ = ['Tube']
