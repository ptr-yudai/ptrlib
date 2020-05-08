# coding: utf-8
from ptrlib.util.encoding import *
from ptrlib.console.color import Color
from abc import ABCMeta, abstractmethod
import threading
import time
from logging import getLogger

logger = getLogger(__name__)

class Tube(metaclass=ABCMeta):
    def __init__(self):
        self.buf = b''

    @abstractmethod
    def _settimeout(self, timeout):
        pass

    @abstractmethod
    def _recv(self, size, timeout):
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        pass

    def unget(self, data):
        self.buf = data + self.buf

    def recv(self, size, timeout):
        """Receive raw data with buffering

        Receive raw data of maximum `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        if size > len(self.bufsize):
            self.buf += self._recv(size, timeout)

        data, self.buf = self.buf[:size], self.buf[size:]
        return data

    def recvonce(self, size, timeout):
        """Receive raw data with buffering

        Receive raw data of size `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        data = b''
        while len(data) < size:
            data += self.recv(size - len(data))

        if len(data) > size:
            self.unget(data[size:])
        return data[:size]


    def recvuntil(self, size=4096, delim, timeout=None):
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

        while data.find(delim) == -1:
            data += self.recv(size, timeout)
        pos = data.find(delim) + len(delim)
        self.unget(data[pos:])
        return data[:pos]

    def recvline(self, size=4096, timeout=None, drop=True):
        line = self.recvuntil(b'\n')
        if drop:
            return line.rstrip()
        return line

    @abstractmethod
    def send(self, data, timeout):
        pass

    def sendline(self, data, timeout=None):
        """Send a line

        Send a line of data.

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        if isinstance(data, str):
            data = str2bytes(data)
        self.send(data + b'\n', timeout)

    def sendafter(self, delim, data, timeout=None):
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
        recv_data = self.recvuntil(delim, timeout)
        self.send(data, timeout)
        return recv_data

    def sendlineafter(self, delim, data, timeout=None):
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
        recv_data = self.recvuntil(delim, timeout)
        self.sendline(data, timeout)
        return recv_data

    def interactive(self, timeout=None):
        """Interactive mode
        """
        def thread_recv():
            while not flag.isSet():
                try:
                    data = self.recv(timeout=0.1)
                    if data is not None:
                        print(bytes2str(data), end="")
                except EOFError:
                    logger.error("interactive: EOF")
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
                    self.sendline(data)
                time.sleep(0.1)
        except KeyboardInterrupt:
            flag.set()

        while th.is_alive():
            th.join(timeout = 0.1)
            time.sleep(0.1)

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def shutdown(self, target):
        pass
