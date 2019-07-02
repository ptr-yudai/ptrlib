# coding: utf-8
from ptrlib.util.encoding import *
from ptrlib.console.color import Color
from abc import ABCMeta, abstractmethod
import threading
import time
from logging import getLogger

logger = getLogger(__name__)

class Tube(metaclass=ABCMeta):
    @abstractmethod
    def _settimeout(self, timeout):
        pass

    @abstractmethod
    def recv(self, size, timeout):
        pass

    @abstractmethod
    def recvonce(self, size, timeout):
        pass

    def recvall(self, size=4096, timeout=None):
        """Receive all data

        Receive all data through the socket.

        Args:
            size (int)   : Data size to receive at once
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        data = b''
        while True:
            part = self.recv(size)
            data += part
        return data

    def recvline(self, timeout=None, drop=True):
        """Receive a line

        Receive a line of raw data through the socket.

        Args:
            timeout (int): Timeout (in second)
            drop (bool)  : Whether or not to strip the newline

        Returns:
            bytes: The received data
        """
        data = b''
        c = None
        while c != b'\n':
            c = self.recvonce(1, timeout)
            if c is None:
                # Timeout
                break
            else:
                data += c
        if drop:
            return data.rstrip()
        else:
            return data

    def recvuntil(self, delim, timeout=None):
        """Receive raw data until `delim` comes

        Args:
            delim (bytes): The delimiter bytes
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        if isinstance(delim, str):
            delim = str2bytes(delim)
        data = b''
        length = len(delim)

        # Create the Boyer-Moore table
        bm_table = [length for i in range(0x100)]
        for (i, c) in enumerate(delim):
            bm_table[c] = length - i - 1

        # Receive data until the delimiter comes
        recv_size = length
        obj = None
        while True:
            # Receive
            obj = self.recvonce(recv_size, timeout)
            if obj is None:
                # Timeout
                break
            else:
                data += obj
            # Search
            i = -1
            j = length - 1
            while j >= 0:
                if data[i] != delim[j]: break
                i, j = i - 1, j - 1
            if j < 0:
                # Delimiter found
                break
            recv_size = max(bm_table[data[i]], length - j)
            i += recv_size
        return data

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

        flag = threading.Event()
        th = threading.Thread(target=thread_recv)
        th.setDaemon(True)
        th.start()

        try:
            while not flag.isSet():
                data = input("{bold}{blue}[ptrlib]${end} ".format(
                    bold=Color.BOLD, blue=Color.BLUE, end=Color.END
                ))
                if data is None:
                    flag.set()
                else:
                    self.sendline(data)
                time.sleep(0.1)
        except KeyboardInterrupt:
            flag.set()

        while th.is_alive():
            th.join(timeout = 0.1)

    @abstractmethod
    def close(self):
        pass
