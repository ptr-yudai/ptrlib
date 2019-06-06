# coding: utf-8
from logging import getLogger
from ptrlib.util.encoding import *
from ptrlib.pwn.tube import *
import socket

logger = getLogger(__name__)


class Socket(Tube):
    def __init__(self, host, port, timeout=None):
        """Create a socket

        Create a new socket and establish a connection to the host.

        Args:
            host (str): The host name or ip address of the server
            port (int): The port number

        Returns:
            Socket: ``Socket`` instance.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        # Create a new socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Establish a connection
        try:
            self.sock.connect((self.host, self.port))
            logger.info("Successfully connected to {0}:{1}".format(self.host, self.port))
        except ConnectionRefusedError as e:
            logger.warning("Connection to {0}:{1} refused".format(self.host, self.port))

    def _settimeout(self, timeout):
        if timeout is None:
            self.sock.settimeout(self.timeout)
        else:
            self.sock.settimeout(timeout)

    def recv(self, size=4096, timeout=None):
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        if size <= 0:
            logger.error("`size` must be larger than 0")
            return None
        try:
            data = self.sock.recv(size)
        except socket.timeout:
            return None
        # No data received
        if len(data) == 0:
            data = None
        return data

    def recvonce(self, size=4, timeout=None):
        """Receive raw data at once

        Receive raw data of `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        data = b''
        if size <= 0:
            logger.error("`size` must be larger than 0")
            return None
        try:
            read_byte = 0
            recv_size = size
            while read_byte < size:
                data += self.sock.recv(recv_size)
                read_byte = len(data)
                recv_size = size - read_byte
        except socket.timeout:
            logger.error("Timeout")
            return None
        return data

    def send(self, data, timeout=None):
        """Send raw data

        Send raw data through the socket

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        self._settimeout(timeout)
        if isinstance(data, str):
            data = str2bytes(data)

        try:
            self.sock.send(data)
        except BrokenPipeError:
            logger.warning("Broken pipe")

    def close(self):
        """Close the socket

        Close the socket.
        This method is called from the destructor.
        """
        self.sock.close()
        logger.info("Connection to {0}:{1} closed".format(self.host, self.port))

    def __del__(self):
        self.close()
