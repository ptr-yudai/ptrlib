import errno
import select
import socket
from logging import getLogger
from typing import Optional, Union
from ptrlib.binary.encoding import bytes2str
from .tube import Tube, tube_is_open

logger = getLogger(__name__)


class Socket(Tube):
    #
    # Constructor
    #
    def __init__(self,
                 host: Union[str, bytes],
                 port: Optional[int]=None,
                 ssl: bool=False,
                 sni: Union[str, bool]=True,
                 **kwargs):
        """Create a socket

        Create a new socket and establish a connection to the host.

        Args:
            host: Host name or ip address
            port: Port number
            ssl : Enable SSL/TLS
            sni : SNI

        Returns:
            Socket: ``Socket`` instance.
        """
        assert isinstance(host, (str, bytes)), \
            "`host` must be either str or bytes"

        # NOTE: We need to initialize _current_timeout before super constructor
        #       because it may call _settimeout_impl
        self._current_timeout = 0
        super().__init__(**kwargs)

        # Interpret host name and port number
        host = bytes2str(host)
        if port is None:
            host = host.strip()
            if host.startswith('nc '):
                _, a, b = host.split()
            elif host.count(':') == 1:
                a, b = host.split(':')
            elif host.count(' ') == 1:
                a, b = host.split()
            else:
                raise ValueError("Port number is not given")
            host, port = a, int(b)

        else:
            port = int(port)
            
        self._host = host
        self._port = port

        # Create a new socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if ssl:
            import ssl as _ssl
            self.context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            self.context.check_hostname = False
            self.context.verify_mode = _ssl.CERT_NONE
            if sni is True:
                self._sock = self.context.wrap_socket(self._sock)
            else:
                self._sock = self.context.wrap_socket(self._sock, server_hostname=sni)

        # Establish a connection
        try:
            self._sock.connect((self._host, self._port))
            logger.info(f"Successfully connected to {self._host}:{self._port}")

        except ConnectionRefusedError as e:
            logger.error(f"Connection to {self._host}:{self._port} refused")
            raise e from None

        self._init_done = True

    #
    # Implementation of Tube methods
    #
    def _settimeout_impl(self,
                         timeout: Union[int, float]):
        """Set timeout

        Args:
            timeout: Timeout in second
        """
        self._current_timeout = timeout

    def _recv_impl(self, size: int) -> bytes:
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the socket.

        Args:
            size: Maximum data size to receive at once

        Returns:
            bytes: The received data

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error
        """
        # NOTE: We cannot rely on the blocking behavior of `recv`
        #       because the socket might be non-blocking mode
        #       due to `_is_alive_impl` on multi-thread environment.
        if self._current_timeout == 0:
            timeout = None
        else:
            timeout = self._current_timeout

        ready, [], [] = select.select([self._sock], [], [], timeout)
        if len(ready) == 0:
            raise TimeoutError("Timeout (_recv_impl)", b'') from None

        try:
            data = self._sock.recv(size)
            if len(data) == 0:
                raise ConnectionResetError("Empty reply") from None

        except BlockingIOError:
            # NOTE: This exception can occur if this method is called
            #       while `_is_alive_impl` is running in multi-thread.
            #       We make `_recv_impl` fail in this case.
            return b''

        except socket.timeout:
            raise TimeoutError("Timeout (_recv_impl)", b'') from None

        except ConnectionAbortedError as e:
            logger.error("Connection aborted")
            raise e from None

        except ConnectionResetError as e:
            logger.error(f"Connection reset by {str(self)}")
            raise e from None

        except OSError as e:
            logger.error("OS Error")
            raise e from None

        return data

    def _send_impl(self, data: bytes) -> int:
        """Send raw data

        Raises:
            ConnectionAbortedError: Connection is aborted by process
            ConnectionResetError: Connection is closed by peer
            TimeoutError: Timeout exceeded
            OSError: System error
        """
        try:
            return self._sock.send(data)

        except BrokenPipeError as e:
            logger.error("Broken pipe")
            raise e from None

        except ConnectionAbortedError as e:
            logger.error("Connection aborted")
            raise e from None

        except ConnectionResetError as e:
            logger.error(f"Connection reset by {str(self)}")
            raise e from None

        except OSError as e:
            logger.error("OS Error")
            raise e from None

    def _close_impl(self):
        """Close socket
        """
        self._sock.close()
        logger.info(f"Connection to {str(self)} closed")

    def _is_alive_impl(self) -> bool:
        """Check if socket is alive
        """
        try:
            # Save timeout value since non-blocking mode will clear it
            timeout = self._sock.gettimeout()
            self._sock.setblocking(False)

            # Connection is closed if recv returns empty buffer
            ret = len(self._sock.recv(1, socket.MSG_PEEK)) == 1

        except BlockingIOError as e:
            ret = True

        except (ConnectionResetError, socket.timeout):
            ret = False

        finally:
            self._sock.setblocking(True)
            self._settimeout_impl(timeout)

        return ret

    def _shutdown_recv_impl(self):
        """Close read
        """
        self._sock.shutdown(socket.SHUT_RD)

    def _shutdown_send_impl(self):
        """Close write
        """
        self._sock.shutdown(socket.SHUT_WR)

    def __str__(self) -> str:
        return f"{self._host}:{self._port}"


    #
    # Custom methods
    #
    @tube_is_open
    def set_keepalive(self,
                      keep_idle: Optional[Union[int, float]]=None,
                      keep_interval: Optional[Union[int, float]]=None,
                      keep_count: Optional[Union[int, float]]=None):
        """Set TCP keep-alive mode

        Send a keep-alive ping once every `keep_interval` seconds if activates
        after `keep_idle` seconds of idleness, and closes the connection
        after `keep_count` failed ping.

        Args:
            keep_idle    : Maximum duration to wait before sending keep-alive ping in second
            keep_interval: Interval to send keep-alive ping in second
            keep_count   : Maximum number of failed attempts
        """
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if keep_idle is not None:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, keep_idle)
        if keep_interval is not None:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, keep_interval)
        if keep_count is not None:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, keep_count)


remote = Socket # alias
