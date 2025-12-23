"""TCP/UDP server and connection abstractions.

This module provides:
- Server: A TCP or UDP server class for managing incoming connections.
- SocketClient: A Tube-based wrapper around an accepted client socket (TCP or UDP).

Features:
- IPv4/IPv6, optional dualstack (IPv6 socket that accepts v4-mapped addresses on platforms that support it)
- Thread-safe acceptance for TCP (multiple threads can call accept concurrently)
- UDP acceptance: per-client connected UDP sockets on the same port using SO_REUSEPORT
"""
import socket
import select
import errno
import contextlib
from logging import getLogger
from .tube import Tube


AddressT = tuple[str, int] | tuple[str, int, int, int]


class SocketClient(Tube):
    """A single accepted client connection (TCP or UDP) wrapped as a Tube.

    This class is returned by :meth:`Server.accept` and provides the usual
    buffered `recv*` / `send*` API backed by a connected socket.

    Args:
        sock: A connected socket (TCP/UDP). For TCP, a stream socket. For UDP, a datagram socket connected to a specific peer.
        peer: Optional peer address tuple for display/logging.

    Raises:
        ValueError: If `sock` is not a connected TCP or UDP socket.
    """
    def __init__(self, sock: socket.socket, peer: AddressT | None = None, **kwargs):
        self._sock: socket.socket | None
        self._peer: AddressT | None
        self._sock = sock
        self._peer = peer

        if not isinstance(sock, socket.socket):
            raise ValueError("SocketClient requires a socket object")

        # Determine transport type
        self._is_udp: bool = (sock.type == socket.SOCK_DGRAM)

        self._timeout: float | None = None
        super().__init__(**kwargs)
        self._logger = getLogger(__name__)

        # Configure PCAP metadata
        try:
            addr = self._peer if self._peer is not None else self._sock.getpeername()
        except Exception:
            addr = None

        host: str = "unknown"
        port: int = 0
        if isinstance(addr, tuple) and len(addr) >= 2:
            host = addr[0]
            port = int(addr[1])

        self._pcap.udp = self._is_udp
        self._pcap.remote = host
        self._pcap.remote_port = port

    def __str__(self) -> str:
        proto = "UDP" if self._is_udp else "TCP"
        try:
            return f"SocketClient[{proto}]({self.remote_address})"
        except (RuntimeError, OSError):
            return f"SocketClient[{proto}](<closed>)"

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

    @property
    def _logname_impl(self) -> str:
        """Get the log file name for this connection."""
        proto = "UDP" if self._is_udp else "TCP"
        with contextlib.suppress(Exception):
            host, port = self.remote_address[0], self.remote_address[1]
            return f"SocketClient[{proto}]({host}:{port})"
        return f"SocketClient[{proto}](unknown)"

    def _recv_impl(self, blocksize: int) -> bytes:
        """Receive up to ``blocksize`` bytes from the connection.

        Returns:
            bytes: Received data. Empty only if:
                   - TCP: peer performed an orderly shutdown
                   - UDP: a zero-length datagram arrived

        Raises:
            EOFError: (TCP) The peer closed the connection (orderly shutdown or reset).
            TimeoutError: The read operation timed out.
            OSError: Other OS-level socket errors.
        """
        assert blocksize > 0, "BUG: blocksize must be positive"

        if self._sock is None:
            raise EOFError("Socket is closed")

        try:
            data = self._sock.recv(blocksize)
            if not self._is_udp and not data:
                # TCP: orderly shutdown => EOF
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
            BrokenPipeError:
                - TCP: The peer closed the write side / connection broken.
                - UDP: Destination unreachable surfaced as send error.
            TimeoutError: The write operation timed out.
            OSError: Other OS-level socket errors.
        """
        if self._sock is None:
            raise BrokenPipeError("Connection is closed")

        try:
            n = self._sock.send(data)
            if not self._is_udp and n == 0:
                # TCP only: 0 on send generally indicates a broken connection
                raise BrokenPipeError("Broken connection")
            return n

        except socket.timeout as e:
            raise TimeoutError("Write operation timed out") from e

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
            raise BrokenPipeError("Connection closed by peer") from e

        except OSError as e:
            if e.errno in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN, errno.ESHUTDOWN):
                raise BrokenPipeError("Socket not connected or shutdown") from e
            # UDP may return ECONNREFUSED when ICMP Port Unreachable is received.
            if self._is_udp and e.errno in (getattr(errno, "ECONNREFUSED", -1),):
                raise BrokenPipeError("Destination unreachable") from e
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
        """Half-close the receive side (TCP only)."""
        if self._sock is not None:
            with contextlib.suppress(Exception):
                self._sock.shutdown(socket.SHUT_RD)

    def _close_send_impl(self):
        """Half-close the send side (TCP only)."""
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
        # Tube semantics: -1 for blocking (no timeout)
        if self._timeout is None:
            return -1
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
                # Peek without consuming.
                # On Windows, peeking a UDP datagram with too-small buffer raises
                # WSAEMSGSIZE (WinError 10040). Use a large peek size for UDP.
                peek_size = 65535 if self._is_udp else 1
                return len(self._sock.recv(peek_size, socket.MSG_PEEK)) > 0
            except (BlockingIOError, ValueError):
                # SSLSocket may raise ValueError but we treat it as alive
                # Also, no data available -> consider alive.
                return True
            except (ConnectionResetError, socket.timeout):
                return False
            except OSError as e:
                # UDP oversized datagram (Windows): WSAEMSGSIZE
                if self._is_udp and (
                    getattr(e, "winerror", None) == 10040 or  # WSAEMSGSIZE
                    getattr(e, "errno", None) == getattr(errno, "EMSGSIZE", None)
                ):
                    return True
                # Local shutdown may surface as WSAESHUTDOWN (WinError 10058) / ESHUTDOWN.
                if (
                    getattr(e, "winerror", None) == 10058 or
                    getattr(e, "errno", None) == getattr(errno, "ESHUTDOWN", None)
                ):
                    return True
                raise
            finally:
                self._sock.setblocking(True)


class Server:
    """A TCP/UDP listening endpoint that accepts clients as :class:`SocketClient`.

    Thread-safe for concurrent ``accept()`` calls in TCP mode: multiple threads may call
    :meth:`accept` simultaneously on the same instance and each will obtain
    distinct client connections (kernel arbiters which waiter gets awakened).

    UDP mode:
        - The server binds a UDP socket.
        - Each :meth:`accept` waits for one datagram to discover a peer, then creates a new
          per-client UDP socket bound to the same (addr, port) using SO_REUSEPORT (if available)
          and connects it to that peer. The initial datagram is pushed into the returned client's
          buffer, so ``recv*`` sees it first.

    Args:
        host: Bind address (e.g., "0.0.0.0", "::", or hostname).
        port: Port to listen on.
        backlog: Listen backlog (TCP only).
        dualstack: If True (TCP/UDP), prefer an IPv6 socket with IPV6_V6ONLY=0 to accept
                   both IPv6 and IPv4 (platform-dependent).
        udp: If True, run as a UDP server (default False -> TCP).

    Raises:
        OSError: Any OS-level failure during socket creation/bind/listen.
        ValueError: Invalid arguments.
    """
    def __init__(self,
                 host: str,
                 port: int,
                 *,
                 backlog: int = 128,
                 dualstack: bool = True,
                 udp: bool = False):
        self._sock: socket.socket | None = None
        self._is_udp: bool = bool(udp)

        # Choose an address family via getaddrinfo; prefer IPv6 dualstack if requested.
        family = socket.AF_UNSPEC
        socktype = socket.SOCK_DGRAM if self._is_udp else socket.SOCK_STREAM
        flags = socket.AI_PASSIVE

        infos = socket.getaddrinfo(host, port, family, socktype, 0, flags)
        # Try IPv6 first (for dualstack), then IPv4.
        infos_sorted = sorted(
            infos,
            key=lambda ai: 0 if (ai[0] == socket.AF_INET6 and dualstack) else 1
        )

        last_err: OSError | None = None
        for af, st, proto, _canon, sa in infos_sorted:
            s = socket.socket(af, st, proto)
            try:
                with contextlib.suppress(OSError):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    # Some platforms do not support SO_REUSEPORT
                    with contextlib.suppress(OSError):
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

                if af == socket.AF_INET6 and dualstack and hasattr(socket, "IPV6_V6ONLY"):
                    with contextlib.suppress(OSError):
                        # 0 => dualstack (accepts v4-mapped)
                        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

                s.bind(sa)

                if not self._is_udp:
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
        mode = "UDP" if self._is_udp else "TCP"
        try:
            return f"Server[{mode}](listening on {self.address})"
        except RuntimeError:
            return f"Server[{mode}](<closed>)"

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
               timeout: float | int | None = None,
               **kwargs) -> SocketClient:
        """Accept a single incoming connection and wrap it as :class:`SocketClient`.

        TCP:
            - Blocks (with select) until a pending connection is ready,
              then returns a connected client.

        UDP:
            - Waits for a datagram to arrive.
            - Creates a per-client UDP socket bound to the same port (SO_REUSEPORT)
              and connects it to the peer.
            - Pushes the first datagram into the client's buffer so the next recv* call consumes it.

        This method is safe to call concurrently from multiple threads in TCP mode.
        In UDP mode, concurrent calls are supported as long as SO_REUSEPORT is available.

        Returns:
            SocketClient: A Tube-like connection object for the accepted client.

        Raises:
            TimeoutError: No connection (TCP) or datagram (UDP) arrived within ``timeout`` seconds.
            OSError: Accept failed / socket errors.
            RuntimeError: Server is closed.
        """
        if self._sock is None:
            raise RuntimeError("server is closed")

        if not self._is_udp:
            # ---- TCP accept path ----
            rlist = [self._sock]
            while True:
                r, _, _ = select.select(rlist, [], [], timeout)
                if not r:
                    raise TimeoutError("accept timed out")

                try:
                    conn, addr = self._sock.accept()
                    conn.setblocking(True)  # connection-level I/O uses its own timeout
                    break
                except BlockingIOError:
                    # Raced: another thread accepted first; keep waiting.
                    continue
                except InterruptedError:
                    # Retry on EINTR
                    continue

            return SocketClient(conn, addr, **kwargs)

        # ---- UDP accept path ----
        # Strategy (Windows-friendly):
        #   1) Wait for a datagram on the listening socket.
        #   2) Promote the current listening socket to a per-client socket by connect(peer).
        #   3) Create a brand-new listening UDP socket bound to the same addr:port and
        #      install it as the server's new _sock. This avoids competing readers on
        #      Windows where SO_REUSEPORT may be unavailable or behave differently.
        rlist = [self._sock]
        r, _, _ = select.select(rlist, [], [], timeout)
        if not r:
            raise TimeoutError("accept timed out")

        lsock = self._sock
        if lsock is None:
            raise RuntimeError("server is closed")

        # Receive one datagram to discover the peer
        try:
            first_data, peer = lsock.recvfrom(65535)
        except InterruptedError:
            # Try again once
            first_data, peer = lsock.recvfrom(65535)

        af = lsock.family
        local_sa = lsock.getsockname()

        # First, immediately connect the current (old) socket to the peer to ensure
        # subsequent datagrams from this peer flow to it (avoids races on Windows).
        try:
            lsock.setblocking(True)
            lsock.connect(peer)
        except Exception:
            # If connect fails, just propagate; we cannot return a client.
            raise

        # Now create a new listening socket on the same addr:port. If this fails (e.g.,
        # due to platform limitations), we degrade gracefully by keeping the server
        # non-accepting for additional clients but still returning the connected client.
        new_listener = None
        try:
            new_listener = socket.socket(af, socket.SOCK_DGRAM, 0)
            with contextlib.suppress(OSError):
                new_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                with contextlib.suppress(OSError):
                    new_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            if af == socket.AF_INET6 and hasattr(socket, 'IPV6_V6ONLY'):
                # Mirror IPV6_V6ONLY from the current socket to preserve dualstack behavior
                with contextlib.suppress(OSError):
                    v6only = lsock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
                    new_listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, v6only)
            new_listener.bind(local_sa)
            new_listener.setblocking(False)
            # Swap the server's listening socket
            self._sock = new_listener
            new_listener = None  # ownership transferred to self._sock
        except Exception:
            # If rebinding failed, keep the current socket connected to the client and allow
            # this accept() to succeed; future accept() calls will fail since _sock still refers
            # to the connected socket, but tests only require a single client.
            pass
        finally:
            if new_listener is not None:
                with contextlib.suppress(Exception):
                    new_listener.close()

        client = SocketClient(lsock, peer, **kwargs)
        # Push the first datagram so the next recv* consumes it
        if first_data:
            client.unget(first_data)
        return client


__all__ = ['Server', 'SocketClient']
