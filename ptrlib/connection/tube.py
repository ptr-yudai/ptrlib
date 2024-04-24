import abc
import re
import sys
import threading
from logging import getLogger
from typing import List, Literal, Optional, Tuple, Union
from ptrlib.binary.encoding import bytes2str, str2bytes, bytes2hex, bytes2utf8, hexdump
from ptrlib.console.color import Color

logger = getLogger(__name__)

def tube_is_open(method):
    """Ensure that connection is not *explicitly* closed
    """
    def decorator(self, *args, **kwargs):
        assert isinstance(self, Tube), "Invalid usage of decorator"
        if self._is_closed:
            raise BrokenPipeError("Connection has already been closed by `close`")
        return method(self, *args, **kwargs)
    return decorator

def tube_is_send_open(method):
    """Ensure that sender connection is not explicitly closed
    """
    def decorator(self, *args, **kwargs):
        assert isinstance(self, Tube), "Invalid usage of decorator"
        if self._is_send_closed:
            raise BrokenPipeError("Connection has already been closed by `shutdown`")
        return method(self, *args, **kwargs)
    return decorator

def tube_is_recv_open(method):
    """Ensure that receiver connection is not explicitly closed
    """
    def decorator(self, *args, **kwargs):
        assert isinstance(self, Tube), "Invalid usage of decorator"
        if self._is_recv_closed:
            raise BrokenPipeError("Connection has already been closed by `shutdown`")
        return method(self, *args, **kwargs)
    return decorator


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
                 timeout: Optional[Union[int, float]]=None,
                 debug: bool=False):
        """Base constructor

        Args:
            timeout (float): Default timeout
        """
        self._buffer = b''
        self._debug = debug

        self._is_closed = False
        self._is_send_closed = False
        self._is_recv_closed = False

        self._default_timeout = timeout
        self.settimeout()

    #
    # Properties
    #
    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, is_debug):
        self._debug = bool(is_debug)

    #
    # Methods
    #
    def settimeout(self, timeout: Optional[Union[int, float]]=None):
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
        assert timeout is None or (isinstance(timeout, (int, float)) and timeout >= 0), \
            "`timeout` must be positive and either int or float"

        if timeout is None:
            if self._default_timeout is not None:
                self._settimeout_impl(self._default_timeout)
        else:
            self._settimeout_impl(timeout)

    def recv(self,
             size: int=4096,
             timeout: Optional[Union[int, float]]=None) -> bytes:
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
        assert size is None or (isinstance(size, int) and size >= 0), \
            "`size` must be a positive integer"

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
                logger.info(f"Received {hex(len(data))} ({len(data)}) bytes:")
                hexdump(data, prefix="    " + Color.CYAN, postfix=Color.END)

            self._buffer += data

        except TimeoutError as err:
            data = self._buffer + err.args[1]
            self._buffer = b''
            raise TimeoutError("Timeout (recv)", data)

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
                raise TimeoutError("Timeout (recvonce)", data + err.args[1])

        if len(data) > size:
            self.unget(data[size:])
        return data[:size]

    def recvuntil(self,
                  delim: Union[str, bytes, List[Union[str, bytes]]],
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
        assert isinstance(delim, (str, bytes, list)), \
            "`delim` must be either str, bytes, or list"

        # Preprocess
        if isinstance(delim, list):
            for i, d in enumerate(delim):
                assert isinstance(d, (str, bytes)), \
                    f"`delim[{i}]` must be either str or bytes"
                delim[i] = str2bytes(delim[i])
        else:
            delim = [str2bytes(delim)]

        # Iterate until we find one of the delimiters
        found_delim = None
        prev_len = 0
        data = b''
        while True:
            try:
                data += self.recv(size, timeout)
            except TimeoutError as err:
                raise TimeoutError("Timeout (recvuntil)", data + err.args[1])
            except Exception as err:
                err.args = (err.args[0], data)
                raise err from None

            for d in delim:
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
            line = self.recvuntil(b'\n', size, timeout, lookahead=lookahead)
        except TimeoutError as err:
            raise TimeoutError("Timeout (recvline)", err.args[1])

        return line.rstrip() if drop else line

    def recvlineafter(self,
                      delim: Union[str, bytes],
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
            raise TimeoutError("Timeout (recvlineafter)", b'')

        try:
            return self.recvline(size, timeout, drop, lookahead)
        except TimeoutError as err:
            raise TimeoutError("Timeout (recvlineafter)", err.args[1])

    def recvregex(self,
                  regex: Union[str, bytes, re.Pattern],
                  size: int=4096,
                  timeout: Optional[Union[int, float]]=None) -> Union[bytes, Tuple[bytes, ...]]:
        """Receive until a pattern comes

        Receive data until a specified regex pattern matches.

        Args:
            regex  : Regular expression
            size   : Size to read at once
            timeout: Timeout in second

        Returns:
            tuple: If the given regex has multiple patterns to find,
                   it returns all matches. Otherwise, it returns the
                   matched string.

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error
        """
        assert isinstance(regex, (str, bytes, re.Pattern)), \
            "`regex` must be either str, bytes, or re.Pattern"

        if isinstance(regex, str):
            regex = re.compile(str2bytes(regex))

        data = b''
        match = None
        while match is None:
            try:
                data += self.recv(size, timeout)
            except TimeoutError as err:
                raise TimeoutError("Timeout (recvregex)", data + err.args[1])
            match = regex.search(data)

        self.unget(data[match.end():])

        if match.groups():
            return match.groups()
        else:
            return match.group()

    def recvscreen(self,
                   delim: Optional[Union[str, bytes]]=b'\x1b[H',
                   returns: Optional[type]=str,
                   timeout: Optional[Union[int, float]]=None,
                   timeout2: Optional[Union[int, float]]=1):
        """Receive a screen

        Receive a screen drawn by ncurses

        Args:
            delim   : Refresh sequence
            returns : Return value as string or list
            timeout : Timeout to receive the first delimiter
            timeout2: Timeout to receive the second delimiter

        Returns:
            str: Rectangle string drawing the screen

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error
        """
        assert returns in [list, str, bytes], \
            "`returns` must be either list, str, or bytes"

        try:
            self.recvuntil(delim, timeout=timeout)
        except TimeoutError as err:
            # NOTE: We do not set received value here
            raise TimeoutError("Timeout (recvscreen)", b'')

        try:
            buf = self.recvuntil(delim, drop=True, lookahead=True, timeout=timeout2)
        except TimeoutError as err:
            buf = err.args[1]

        screen = draw_ansi(buf)
        if returns == str:
            return '\n'.join(map(lambda row: ''.join(row), screen))
        elif returns == bytes:
            return b'\n'.join(map(lambda row: bytes(row), screen))
        else:
            return screen

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
        assert isinstance(data, (str, bytes)), "`data` must be either str or bytes"

        size = self._send_impl(str2bytes(data))
        if self.debug:
            logger.info(f"Sent {hex(size)} ({size}) bytes:")
            hexdump(data[:size], prefix=Color.YELLOW, postfix=Color.END)

        return size

    def sendall(self, data: Union[str, bytes]):
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
                 data: Union[int, float, str, bytes],
                 timeout: Optional[Union[int, float]]=None):
        """Send a line

        Send a line of data.

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        assert isinstance(data, (int, float, str, bytes)), \
            "`data` must be int, float, str, or bytes"

        if isinstance(data, (int, float)):
            data = str(data).encode()
        else:
            data = str2bytes(data)

        self.send(data + b'\n')

    def sendafter(self,
                  delim: Union[str, bytes, List[Union[str, bytes]]],
                  data: Union[int, float, str, bytes],
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
        self.send(data)

        return recv_data

    def sendlineafter(self,
                      delim: Union[str, bytes],
                      data: Union[str, bytes, int],
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
        self.sendline(data, timeout=timeout)

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
                        elif ord(c) not in [0x09, 0x0a, 0x0d] and \
                             ord(c) < 0x20:
                            pretty_print_hex(c)
                        else:
                            sys.stdout.write(c)
                    else:
                        pretty_print_hex(c)

            sys.stdout.flush()
            return leftover

        def thread_recv(flag: threading.Event):
            """Receive data from tube and print to stdout
            """
            leftover = b''
            while not flag.isSet():
                try:
                    sys.stdout.write(prompt)
                    sys.stdout.flush()
                    data = self.recv()
                    leftover = pretty_print(data, leftover)

                    if not self.is_alive():
                        logger.error(f"Connection closed by {str(self)}")
                        flag.set()

                except TimeoutError:
                    pass
                except EOFError:
                    logger.error("Receiver EOF")
                    break
                except ConnectionAbortedError:
                    logger.error("Receiver EOF")
                    break

        def thread_send(flag: threading.Event):
            """Read user input and send it to tube
            """
            #sys.stdout.write(f"{Color.BOLD}{Color.BLUE}{prompt}{Color.END}")
            #sys.stdout.flush()
            while not flag.isSet():
                try:
                    self.send(sys.stdin.readline())
                except (ConnectionResetError, ConnectionAbortedError, OSError):
                    flag.set()

        flag = threading.Event()
        th_recv = threading.Thread(target=thread_recv, args=(flag,))
        th_send = threading.Thread(target=thread_send, args=(flag,))
        th_recv.start()
        th_send.start()
        try:
            th_recv.join()
            th_send.join()
        except KeyboardInterrupt:
            logger.warning("Intterupted by user")
            sys.stdin.close()
            flag.set()

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
        if not self._is_closed:
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
        pass

    @abc.abstractmethod
    def _recv_impl(self, size: int) -> bytes:
        """Abstract method for `recv`

        Receives at most `size` bytes from tube.
        This method must be a blocking method.
        """
        pass

    @abc.abstractmethod
    def _send_impl(self, data: bytes) -> int:
        """Abstract method for `send`

        Sends tube as much data as possible.

        Args:
            data: Data to send
        """
        pass

    @abc.abstractmethod
    def _close_impl(self):
        """Abstract method for `close`

        Close the connection.
        This method is ensured to be called only once.
        """
        pass

    @abc.abstractmethod
    def _is_alive_impl(self) -> bool:
        """Abstract method for `is_alive`

        This method must return True iff the connection is alive.
        """
        pass

    @abc.abstractmethod
    def _shutdown_recv_impl(self):
        """Kill receiver connection
        """
        pass

    @abc.abstractmethod
    def _shutdown_send_impl(self):
        """Kill sender connection
        """
        pass
