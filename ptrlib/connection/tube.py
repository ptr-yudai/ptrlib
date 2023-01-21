# coding: utf-8
import subprocess
from typing import Any, Optional, Tuple, Union, overload
try:
    from typing import Literal
except:
    from typing_extensions import Literal
from ptrlib.binary.encoding import *
from ptrlib.console.color import Color
from abc import ABCMeta, abstractmethod
import re
import sys
import threading
import time
from logging import getLogger

logger = getLogger(__name__)


class Tube(metaclass=ABCMeta):
    def __init__(self):
        self.buf = b''

    @abstractmethod
    def _settimeout(self, timeout: Optional[Union[int, float]]):
        pass

    @abstractmethod
    def _recv(self, size: int, timeout: Union[int, float]) -> Optional[bytes]:
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        pass

    def unget(self, data: Union[str, bytes]):
        if isinstance(data, str):
            data = str2bytes(data)
        self.buf = data + self.buf

    def recv(self, size: int=4096, timeout: Optional[Union[int, float]]=None) -> bytes:
        """Receive raw data with buffering

        Receive raw data of maximum `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        if not self.buf:
            data = self._recv(size, timeout=-1)
            if data is not None:
                self.buf += data

        data, self.buf = self.buf[:size], self.buf[size:]
        return data

    def recvonce(self, size: int, timeout: Optional[Union[int, float]]=None) -> bytes:
        """Receive raw data with buffering

        Receive raw data of size `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        data = b''
        while len(data) < size:
            data += self.recv(size - len(data))

        if len(data) > size:
            self.unget(data[size:])
        return data[:size]


    def recvuntil(self, delim: Union[str, bytes], size: int=4096, timeout: Optional[Union[int, float]]=None, drop: bool=False, lookahead: bool=False) -> bytes:
        """Receive raw data until `delim` comes

        Args:
            size (int)   : The data size to receive at once
            delim (bytes): The delimiter bytes
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        if isinstance(delim, str):
            delim = str2bytes(delim)
        data = b''

        self._settimeout(timeout)
        while data.find(delim) == -1:
            data += self.recv(size, -1)

        found_pos = data.find(delim)
        result_len = found_pos if drop else found_pos + len(delim)
        consumed_len = found_pos if lookahead else found_pos + len(delim)
        self.unget(data[consumed_len:])
        return data[:result_len]

    def recvline(self, size: int=4096, timeout: Optional[Union[int, float]]=None, drop: bool=True) -> bytes:
        line = self.recvuntil(b'\n', size, timeout)
        if drop:
            return line.rstrip()
        return line

    def recvlineafter(self, delim: Union[str, bytes], size: int=4096, timeout: Optional[Union[int, float]]=None, drop: bool=True) -> bytes:
        self.recvuntil(delim, size, timeout)
        return self.recvline(size, timeout, drop)

    # TODO: proper typing
    @overload
    def recvregex(self, regex: Union[str, bytes], size: int=4096, discard: Literal[True]=True, timeout: Optional[Union[int, float]]=None) -> bytes: ...

    @overload
    def recvregex(self, regex: Union[str, bytes], size: int=4096, discard: Literal[False]=False, timeout: Optional[Union[int, float]]=None) -> Tuple[bytes, bytes]: ...

    def recvregex(self, regex: Union[str, bytes], size: int=4096, discard: bool=True, timeout: Optional[Union[int, float]]=None) -> Union[bytes, Tuple[bytes, bytes]]:
        """Receive until a pattern comes

        Receive data until a specified regex pattern matches.

        Args:
            regex (bytes): Regex
            size (int)   : Size to read at once
            timeout (int): Timeout (in second)

        Returns:
            tuple: If the given regex has multiple patterns to find,
                   it returns all matches. Otherwise, it returns the
                   match string. If discard is false, it also returns
                   all data received so far along with the matches.
        """
        if not isinstance(regex, bytes):
            regex = str2bytes(regex)

        p = re.compile(regex)
        data = b''

        self._settimeout(timeout)
        r = None
        while r is None:
            data += self.recv(size, timeout=-1)
            r = p.search(data)

        pos = r.end()
        self.unget(data[pos:])

        group = r.group()
        groups = r.groups()
        if groups:
            if discard:
                return groups
            else:
                return groups, data[:pos]
        else:
            if discard:
                return group
            else:
                return group, data[:pos]

    @abstractmethod
    def send(self, data: bytes):
        pass

    @abstractmethod
    def _socket(self) -> Optional[Any]:
        pass

    def sendline(self, data: Union[str, bytes], timeout: Optional[Union[int, float]]=None):
        """Send a line

        Send a line of data.

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        if isinstance(data, str):
            data = str2bytes(data)
        elif isinstance(data, int):
            data = str(data).encode()

        self.send(data + b'\n')

    def sendafter(self, delim: Union[str, bytes], data: Union[str, bytes, int], timeout: Optional[Union[int, float]]=None):
        """Send raw data after a deliminater

        Send raw data after `delim` is received.

        Args:
            delim (bytes): The deliminater
            data (bytes) : Data to send
            timeout (int): Timeout (in second)

        Returns:
            bytes: Received bytes before `delim` comes.
        """
        if isinstance(data, str):
            data = str2bytes(data)
        elif isinstance(data, int):
            data = str(data).encode()

        recv_data = self.recvuntil(delim, timeout=timeout)
        self.send(data)

        return recv_data

    def sendlineafter(self, delim: Union[str, bytes], data: Union[str, bytes, int], timeout: Optional[Union[int, float]]=None) -> bytes:
        """Send raw data after a deliminater

        Send raw data with newline after `delim` is received.

        Args:
            delim (bytes): The deliminater
            data (bytes) : Data to send
            timeout (int): Timeout (in second)

        Returns:
            bytes: Received bytes before `delim` comes.
        """
        if isinstance(data, str):
            data = str2bytes(data)
        elif isinstance(data, int):
            data = str(data).encode()

        recv_data = self.recvuntil(delim, timeout=timeout)
        self.sendline(data, timeout=timeout)

        return recv_data

    def sh(self, timeout: Optional[Union[int, float]]=None):
        """Alias for interactive
        """
        self.interactive(timeout)

    def interactive(self, timeout: Optional[Union[int, float]]=None):
        """Interactive mode
        """
        def thread_recv():
            while not flag.isSet():
                try:
                    data = self.recv(size=4096, timeout=0.1)
                    if data is not None:
                        sys.stdout.write(bytes2str(data))
                        sys.stdout.flush()
                except TimeoutError:
                    pass
                except EOFError:
                    logger.error("Receiver EOF")
                    break
                except ConnectionAbortedError:
                    logger.error("Receiver EOF")
                    break
                time.sleep(0.1)

        flag = threading.Event()
        th = threading.Thread(target=thread_recv)
        th.setDaemon(True)
        th.start()

        try:
            while not flag.isSet():
                data = input("{bold}{blue}[ptrlib]${end} ".format(
                    bold=Color.BOLD, blue=Color.BLUE, end=Color.END
                ))
                if self._socket() is None:
                    logger.error("Connection already closed")
                    break
                if data is None:
                    flag.set()
                else:
                    try:
                        self.sendline(data)
                    except ConnectionAbortedError:
                        logger.error("Sender EOF")
                        break
                time.sleep(0.1)
        except KeyboardInterrupt:
            flag.set()

        while th.is_alive():
            th.join(timeout = 0.1)
            time.sleep(0.1)

    def __enter__(self):
        return self

    def __exit__(self, e_type, e_value, traceback):
        self.close()

    @abstractmethod
    def is_alive(self) -> bool:
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def shutdown(self, target: Literal['send', 'recv']):
        pass
