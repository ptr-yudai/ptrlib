# coding: utf-8
from logging import getLogger
from ptrlib.util.encoding import *
from ptrlib.pwn.tube import *
import socket

logger = getLogger(__name__)


class Socket(Tube):
    def __init__(self, host, port=None, timeout=None):
        """Create a socket

        Create a new socket and establish a connection to the host.

        Args:
            host (str): The host name or ip address of the server
            port (int): The port number

        Returns:
            Socket: ``Socket`` instance.
        """
        super().__init__()

        if isinstance(host, bytes):
            host = bytes2str(host)

        if port is None:
            host = host.strip()
            if host.startswith('nc '):
                _, a, b = host.split()
                host, port = a, int(b)
            elif host.count(':') == 1:
                a, b = host.split(':')
                host, port = a, int(b)
            elif host.count(' ') == 1:
                a, b = host.split()
                host, port = a, int(b)
            else:
                raise ValueError("Specify port number")

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
            err = "Connection to {0}:{1} refused".format(self.host, self.port)
            logger.warning(err)
            raise e from None

    def _settimeout(self, timeout):
        if timeout is None:
            self.sock.settimeout(self.timeout)
        elif timeout > 0:
            self.sock.settimeout(timeout)

    def _socket(self):
        return self.sock

    def _recv(self, size=4096, timeout=None):
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
            raise TimeoutError("Receive timeout") from None
        except ConnectionAbortedError as e:
            logger.warning("Connection aborted by the host")
            raise e from None

        # No data received
        if len(data) == 0:
            data = None
        return data

    def send(self, data):
        """Send raw data

        Send raw data through the socket

        Args:
            data (bytes) : Data to send
        """
        if isinstance(data, str):
            data = str2bytes(data)

        try:
            self.sock.send(data)
        except BrokenPipeError as e:
            logger.warning("Broken pipe")
            raise e from None
        except ConnectionAbortedError as e:
            logger.warning("Connection aborted by the host")
            raise e from None

    def close(self):
        """Close the socket

        Close the socket.
        This method is called from the destructor.
        """
        if self.sock:
            self.sock.close()
            self.sock = None
            logger.info("Connection to {0}:{1} closed".format(self.host, self.port))

    def shutdown(self, target):
        """Kill one connection

        Close send/recv socket.

        Args:
            target (str): Connection to close (`send` or `recv`)
        """
        if target in ['write', 'send', 'stdin']:
            self.sock.shutdown(socket.SHUT_WR)

        elif target in ['read', 'recv', 'stdout', 'stderr']:
            self.sock.shutdown(socket.SHUT_RD)

        else:
            logger.error("You must specify `send` or `recv` as target.")

    def is_alive(self, timeout=None):
        try:
            self._settimeout(timeout)
            data = self.sock.recv(1, socket.MSG_PEEK)
            return True
        except BlockingIOError:
            return False
        except ConnectionResetError:
            return False
        except socket.timeout:
            return False

    def __del__(self):
        self.close()

# alias
remote = Socket
