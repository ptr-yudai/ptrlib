"""TCP server and connection abstractions.

This module provides the `Server` class for creating and managing TCP listening sockets,
and the `TCPConnection` class for handling individual accepted TCP connections with a
buffered send/receive API. Supports IPv4, IPv6, dual-stack sockets, and thread-safe
acceptance of incoming connections.

Classes:
    Server: A TCP server class for managing incoming connections.
    TCPConnection: A TCP connection class for handling individual client connections.
"""
import socket
import select
import errno
import contextlib
from logging import getLogger
from .tube import Tube


AddressT = tuple[str, int] | tuple[str, int, int, int]

class TCPConnection(Tube):
    """A single accepted TCP connection wrapped as a Tube.

    This class is returned by :meth:`Server.accept` and provides the usual
    buffered `recv*` / `send*` API backed by a connected socket.

    Args:
        sock: A connected socket (already accepted).
        peer: Optional peer address tuple for display/logging.

    Raises:
        ValueError: If `sock` is not a connected TCP socket.
    """
    def __init__(self, sock: socket.socket, peer: AddressT | None = None, **kwargs):
        self._sock: socket.socket | None
        self._peer: AddressT | None
        self._sock = sock
        self._peer = peer

        if not isinstance(sock, socket.socket) or sock.type != socket.SOCK_STREAM:
            raise ValueError("TCPConnection requires a connected TCP socket")

        self._timeout: float | None = None
        super().__init__(**kwargs)
        self._logger = getLogger(__name__)

    def __str__(self) -> str:
        try:
            return f"TCPConnection({self.remote_address})"
        except RuntimeError:
            return "TCPConnection(<closed>)"

    # ---- Properties ------------------------------------------------------

    @property
    def remote_address(self) -> AddressT:
        """Return the peer (remote) address.

        Raises:
            RuntimeError: If the socket is closed.
        """
        if self._sock is None:
            raise RuntimeError("Connection is closed")

        return self._sock.getpeername()

    @property
    def local_address(self) -> AddressT:
        """Return the local address.

        Raises:
            RuntimeError: If the socket is closed.
        """
        if self._sock is None:
            raise RuntimeError("Connection is closed")

        return self._sock.getsockname()

    # ---- Abstracts ------------------------------------------------------

    def _recv_impl(self, blocksize: int) -> bytes:
        """Receive up to ``blocksize`` bytes from the connection.

        Returns:
            bytes: Received data. Empty only if peer performed an orderly shutdown.

        Raises:
            EOFError: The peer closed the connection (orderly shutdown or reset).
            TimeoutError: The read operation timed out.
            OSError: Other OS-level socket errors.
        """
        assert blocksize > 0, "BUG: blocksize must be positive"

        if self._sock is None:
            raise EOFError("Socket is closed")

        try:
            data = self._sock.recv(blocksize)
            if not data:
                raise EOFError("Connection closed by peer")
            return data

        except socket.timeout as e:
            raise TimeoutError("Read operation timed out") from e

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            raise EOFError("Connection reset by peer") from e

        except OSError as e:
            if e.errno in (errno.ECONNRESET, errno.ENOTCONN, errno.ESHUTDOWN):
                raise EOFError("Socket not connected or shutdown") from e
            raise

    def _send_impl(self, data: bytes) -> int:
        """Send a chunk of bytes to the connection (single syscall).

        Returns:
            int: Number of bytes written (may be less than ``len(data)``).

        Raises:
            BrokenPipeError: The peer closed the write side / connection broken.
            TimeoutError: The write operation timed out.
            OSError: Other OS-level socket errors.
        """
        if self._sock is None:
            raise BrokenPipeError("Connection is closed")

        try:
            n = self._sock.send(data)
            if n == 0:
                raise BrokenPipeError("Connection is broken")
            return n

        except socket.timeout as e:
            raise TimeoutError("Write operation timed out") from e

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
            raise BrokenPipeError("Connection closed by peer") from e

        except OSError as e:
            if e.errno in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN, errno.ESHUTDOWN):
                raise BrokenPipeError("Socket not connected or shutdown") from e
            raise

    def _close_impl(self):
        """Close the connection and release resources.

        This method is best-effort and suppresses close/shutdown errors.
        """
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(Exception):
                sock.close()

    def _close_recv_impl(self):
        """Half-close the receive side.

        Raises:
            (never)
        """
        if self._sock is not None:
            with contextlib.suppress(Exception):
                self._sock.shutdown(socket.SHUT_RD)

    def _close_send_impl(self):
        """Half-close the send side.

        Raises:
            (never)
        """
        if self._sock is not None:
            with contextlib.suppress(Exception):
                self._sock.shutdown(socket.SHUT_WR)

    def _settimeout_impl(self, timeout: float):
        if self._sock is None:
            return

        if timeout < 0:
            self._sock.settimeout(None)
            self._timeout = None
        else:
            self._sock.settimeout(timeout)
            self._timeout = timeout

    def _gettimeout_impl(self) -> float:
        if self._timeout is None:
            return 0.0
        return self._timeout

    def _is_alive_impl(self) -> bool:
        """Check if the remote endpoint is still reachable.

        Returns:
            bool: True if the connection is alive, False otherwise.
        """
        if self._sock is None:
            return False

        with self.timeout(-1):
            try:
                self._sock.setblocking(False)
                return self._sock.recv(1, socket.MSG_PEEK) == 1
            except (BlockingIOError, ValueError):
                # SSLSocket may raise ValueError but we treat it as alive
                return True
            except (ConnectionResetError, socket.timeout):
                return False
            finally:
                self._sock.setblocking(True)


class Server:
    """A TCP listening socket that accepts connections as :class:`TCPConnection`.

    Thread-safe for concurrent ``accept()`` calls: multiple threads may call
    :meth:`accept` simultaneously on the same instance and each will obtain
    distinct client connections (kernel arbiters which waiter gets awakened).

    Args:
        host: Bind address (e.g., "0.0.0.0", "::", or hostname).
        port: TCP port to listen on.
        backlog: Listen backlog.
        reuse_addr: Set SO_REUSEADDR (default True).
        reuse_port: Set SO_REUSEPORT if available (default False).
        dualstack: If True, prefer an IPv6 socket with IPV6_V6ONLY=0 to accept
                   both IPv6 and IPv4 (platform-dependent).

    Raises:
        OSError: Any OS-level failure during socket creation/bind/listen.
        ValueError: Invalid arguments.
    """
    def __init__(self,
                 host: str,
                 port: int,
                 *,
                 backlog: int = 128,
                 dualstack: bool = True):
        self._sock: socket.socket | None = None

        # Choose an address family via getaddrinfo; prefer IPv6 dualstack if requested.
        family = socket.AF_UNSPEC
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
        # Try IPv6 first (for dualstack), then IPv4.
        infos_sorted = sorted(
            infos,
            key=lambda ai: 0 if (ai[0] == socket.AF_INET6 and dualstack) else 1
        )

        last_err: OSError | None = None
        for af, socktype, proto, _canon, sa in infos_sorted:
            s = socket.socket(af, socktype, proto)
            try:
                with contextlib.suppress(OSError):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    # Some platform does not support SO_REUSEPORT
                    with contextlib.suppress(OSError):
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

                if af == socket.AF_INET6 and dualstack and hasattr(socket, "IPV6_V6ONLY"):
                    with contextlib.suppress(OSError):
                        # 0 => dualstack (accepts v4-mapped)
                        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

                s.bind(sa)
                s.listen(backlog)
                s.setblocking(False)
                self._sock = s
                return

            except OSError as e:
                last_err = e
                with contextlib.suppress(Exception):
                    s.close()
                continue

        assert last_err is not None
        raise last_err

    def __str__(self) -> str:
        try:
            return f"Server(listening on {self.address})"
        except RuntimeError:
            return "Server(<closed>)"

    def __del__(self):
        self.close()

    # --- Properties -------------------------------------------------------

    @property
    def fd(self) -> int:
        """Return the underlying listening FD.

        Raises:
            RuntimeError: If the server is closed.
        """
        if self._sock is None:
            raise RuntimeError("Server is closed")

        return self._sock.fileno()

    @property
    def address(self) -> AddressT:
        """Return the bound (host, port[, flowinfo, scopeid]) address tuple.

        Raises:
            RuntimeError: If the server is closed.
        """
        if self._sock is None:
            raise RuntimeError("Server is closed")

        return self._sock.getsockname()

    def close(self) -> None:
        """Close the listening socket.

        Raises:
            (never)
        """
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()

    def accept(self,
               accept_timeout: float | int | None = None,
               **kwargs) -> TCPConnection:
        """Accept a single incoming connection and wrap it as :class:`TCPConnection`.

        This method is safe to call concurrently from multiple threads.

        Returns:
            TCPConnection: A Tube-like connection object for the accepted client.

        Raises:
            TimeoutError: No connection arrived within ``timeout`` seconds.
            OSError: Accept failed due to an OS error (e.g., EMFILE/ENFILE).
            RuntimeError: Server is closed.
        """
        if self._sock is None:
            raise RuntimeError("server is closed")

        # Block in select() rather than changing SO timeout (thread-safe).
        rlist = [self._sock]
        while True:
            r, _, _ = select.select(rlist, [], [], accept_timeout)
            if not r:
                raise TimeoutError("accept timed out")

            try:
                conn, addr = self._sock.accept()
                conn.setblocking(True) # connection-level I/O uses its own timeout
                break
            except BlockingIOError:
                # Raced: another thread accepted first; keep waiting.
                continue
            except InterruptedError:
                # Retry on EINTR
                continue

        return TCPConnection(conn, addr, **kwargs)

__all__ = ['Server', 'TCPConnection']
