"""A flexible TCP socket connection class with optional SSL/TLS support.

This module provides the `Socket` class, which normalizes various address notations,
establishes TCP connections, and supports SSL/TLS with configurable SNI.
It offers methods for sending, receiving, keep-alive configuration, and out-of-band data.

Classes:
    Socket: A flexible TCP socket connection class with optional SSL/TLS support.

Typical usage:
    sock = Socket("example.com:443", ssl=True)
    sock.send(b"GET / HTTP/1.0\r\n\r\n")
    data = sock.recv(4096)
"""
import contextlib
import errno
import re
import shlex
import socket
import ssl as _ssl
from logging import getLogger
from urllib.parse import urlparse
from .tube import Tube


class Socket(Tube):
    """A flexible TCP socket connection class with optional SSL/TLS support.
    """
    def __init__(self,
                 host: str,
                 port: int | None = None,
                 ssl: bool = False,
                 sni: str | bool = True,
                 udp: bool = False,
                 connect_timeout: float | None = None,
                 **kwargs):
        """Create and connect a TCP socket.

        This constructor accepts multiple notations and normalizes them to (host, port),
        then creates a TCP connection. If ``ssl=True``, the socket is wrapped with TLS.

        Args:
            host: Host name of the remote server.
            port: Port number.
            ssl: Enable SSL/TLS for the connection if True.
            sni: Server Name Indication (SNI) for the connection.
            udp: Use UDP for the connection if True.
            connect_timeout: Timeout (seconds) for establishing the connection.
                              None keeps the OS default behavior.
            debug: Debug mode for I/O tracing. ('none', 'plain', or 'hex')
            quiet: Suppress output if True.
            pcap: File path to the pcap log file.

        Accepted address forms:
            - Separate host/port:
                ``Socket("example.com", 443)``
            - Host:port (IPv4/hostname):
                ``Socket("example.com:443")``
            - URI:
                ``Socket("tcp://example.com:443")``
            - IPv6 with brackets:
                ``Socket("[2001:db8::1]:443")``, ``Socket("tcp://[2001:db8::1]:443")``
            - netcat-like:
                ``Socket("nc example.com 443")``,
                ``Socket("ncat example.com 443")``,
                ``Socket("netcat example.com 443")``

        Transport:
            - Set ``udp=True`` or use the ``udp://`` scheme to select UDP (SOCK_DGRAM).
            - TLS (``ssl=True``) is **only valid for TCP**.

        TLS/SNI:
            If ``ssl`` is True, a default SSL context is used with hostname checks disabled
            (no certificate verification). ``sni`` controls the SNI server name:
              - ``True``  -> use the resolved host as server_hostname
              - ``False`` -> disable SNI (server_hostname=None)
              - ``str``   -> use the given name

        Raises:
            ValueError: When the port cannot be determined from the inputs.
            socket.gaierror: DNS resolution failure.
            ConnectionRefusedError: Cannot connect to the specified host/port.
            TimeoutError: Connection timeout.
            OSError: Any underlying OS/socket error during connect.
            _ssl.SSLError: TLS negotiation failure when ``ssl=True``.
        """
        self._host: str
        self._port: int
        self._timeout: float | None = None
        self._ssl_enabled = bool(ssl)
        self._sni = sni
        self._connect_timeout: float | None = connect_timeout
        self._sock: socket.socket | None = None
        self._oob_flag = False
        self._is_udp: bool = bool(udp)

        # Detect scheme "udp://..." to auto-enable UDP
        lower = host.strip().lower()
        if lower.startswith("udp://"):
            self._is_udp = True

        if self._is_udp and self._ssl_enabled:
            raise ValueError("SSL/TLS is not supported over UDP")

        self._host, self._port = self._parse_host_port(host, port)

        super().__init__(**kwargs)
        self._logger = getLogger(__name__)

        self._pcap.udp = self._is_udp
        self._pcap.remote = self._host
        self._pcap.remote_port = self._port

        try:
            if not self._is_udp:
                # ---- TCP ----
                self._sock = socket.create_connection(
                    (self._host, self._port),
                    timeout=self._connect_timeout
                )
                # Restore blocking mode so I/O timeouts are controlled by Tube
                with contextlib.suppress(OSError):
                    self._sock.settimeout(None)
                with contextlib.suppress(OSError):
                    self._sock.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1)

                if self._ssl_enabled:
                    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    if sni is False:
                        server_hostname = None
                    elif sni is True:
                        server_hostname = host
                    else:
                        server_hostname = sni
                    self._sock = ctx.wrap_socket(self._sock, server_hostname=server_hostname)

                self._log_info(f"Successfully connected to {self._host}:{self._port} (TCP)")

            else:
                # ---- UDP ----
                # Resolve possible addresses and prefer IPv6 first to match Server's default
                # dualstack preference. Try each candidate until connect succeeds.
                infos = socket.getaddrinfo(self._host, self._port, 0, socket.SOCK_DGRAM)
                infos_sorted = sorted(
                    infos,
                    key=lambda ai: 0 if ai[0] == socket.AF_INET6 else 1
                )

                last_err: Exception | None = None
                for af, socktype, proto, _cn, sa in infos_sorted:
                    s = socket.socket(af, socktype, proto)
                    try:
                        if self._connect_timeout is not None:
                            s.settimeout(self._connect_timeout)
                        # UDP connect does not send packets; it just fixes default peer & filters input.
                        s.connect(sa)
                        if self._connect_timeout is not None:
                            s.settimeout(None)
                        self._sock = s
                        last_err = None
                        break
                    except Exception as e:
                        last_err = e
                        with contextlib.suppress(Exception):
                            s.close()
                        continue

                if self._sock is None:
                    assert last_err is not None
                    raise last_err

                self._log_info(f"Successfully connected to {self._host}:{self._port} (UDP)")

        except ConnectionRefusedError:
            self._log_error(f"Connection to {self._host}:{self._port} refused")
            raise

    def __str__(self) -> str:
        proto = "UDP" if self._is_udp else "TCP"
        return f"Socket[{proto}]({self._host}:{self._port})"

    # --- Abstracts --------------------------------------------------------

    @property
    def _logname_impl(self) -> str:
        """Get the log file name for this process.
        """
        proto = "UDP" if self._is_udp else "TCP"
        return f'Socket[{proto}]({self._host}:{self._port})'

    def _recv_impl(self, blocksize: int) -> bytes:
        """Low-level receive from the socket.

        Reads up to ``blocksize`` bytes using the current socket timeout.

        Returns:
            bytes: The received bytes. For UDP, one datagram is read and may be
                   **truncated** to ``blocksize`` if shorter buffer is provided.

        Raises:
            EOFError:
                - (TCP) Peer closed the connection, reset, or socket not connected.
                - (UDP) Rarely, some platforms report ICMP errors as connection reset.
            TimeoutError: The read operation timed out.
            BrokenPipeError: (rare) Connection broken during receive.
            OSError: Other unforeseen OS-level socket errors.
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

        except BlockingIOError:
            return b"" # Timeout is set to 0 (non-blocking) but no data available

        except socket.timeout as e:
            raise TimeoutError(f"Read operation timed out ({self._timeout}s)") from e

        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError) as e:
            # TCP reset => EOF, UDP ICMP errors may surface as reset on some stacks
            raise EOFError("Connection closed by peer") from e

        except OSError as e:
            if e.errno in (errno.ECONNRESET, errno.ENOTCONN, errno.ESHUTDOWN):
                raise EOFError("Socket not connected or shutdown") from e
            raise

    def _send_impl(self, data: bytes) -> int:
        """Low-level send to the socket.

        For TCP, a single send syscall (may be partial). For UDP, attempts to send
        the whole datagram in one call; partial sends are unusual but possible on
        some platforms.

        Returns:
            int: Number of bytes written (>= 0).

        Raises:
            BrokenPipeError:
                - (TCP) Peer closed the write side / connection broken.
                - (UDP) Destination unreachable surfaced as send error.
            TimeoutError: The write operation timed out.
            OSError: Other OS-level socket errors.
        """
        if self._sock is None:
            raise BrokenPipeError("Socket is closed")

        flags = socket.MSG_OOB if self._oob_flag else 0

        try:
            n = self._sock.send(data, flags)
            if not self._is_udp and n == 0:
                # TCP only: 0 on send generally indicates a broken connection
                raise BrokenPipeError("Broken connection")
            return n

        except socket.timeout as e:
            raise TimeoutError("Timeout (_send_impl)") from e

        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError) as e:
            raise BrokenPipeError("Connection closed by peer") from e

        except OSError as e:
            if e.errno in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN, errno.ESHUTDOWN):
                raise BrokenPipeError("Socket not connected or shutdown") from e
            # UDP may return ECONNREFUSED when ICMP Port Unreachable is received.
            if self._is_udp and e.errno in (getattr(errno, "ECONNREFUSED", -1),):
                raise BrokenPipeError("Destination unreachable") from e
            raise

    def _close_impl(self):
        """Close the socket and release all resources.

        This method is best-effort and does not propagate exceptions.
        """
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(Exception):
                sock.close()

    def _close_recv_impl(self):
        """Close the receive end of the connection (half-close).

        This method is only effective for TCP sockets.
        """
        if self._sock is not None:
            with contextlib.suppress(Exception):
                self._sock.shutdown(socket.SHUT_RD)

    def _close_send_impl(self):
        """Close the send end of the connection (half-close).

        This method is only effective for TCP sockets.
        """
        if self._sock is not None:
            with contextlib.suppress(Exception):
                self._sock.shutdown(socket.SHUT_WR)

    def _settimeout_impl(self, timeout: float):
        """Set socket timeout (Tube semantics).

        Args:
            timeout: Negative -> blocking; non-negative -> seconds.

        Raises:
            OSError: If the underlying socket rejects the timeout (rare).
            ValueError: Invalid timeout value.
        """
        if self._sock is None:
            return

        if timeout < 0:
            self._sock.settimeout(None)
            self._timeout = None
        else:
            self._sock.settimeout(timeout)
            self._timeout = timeout

    def _gettimeout_impl(self) -> float:
        """Get current timeout (Tube semantics).

        Returns:
            float: -1 for blocking (no timeout), or the current timeout in seconds.
        """
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
                # NOTE:
                #   On Windows, peeking a UDP datagram with a too-small buffer raises
                #   WSAEMSGSIZE (WinError 10040). Use a large peek size for UDP and
                #   treat EMSGSIZE as "alive" (data is available, just larger than buffer).
                peek_size = 65535 if self._is_udp else 1
                return len(self._sock.recv(peek_size, socket.MSG_PEEK)) > 0
            except (BlockingIOError, ValueError):
                # Non-blocking socket has no data, or SSL socket can't be peeked.
                # Treat as "alive" because we can't conclude it's dead.
                return True
            except BrokenPipeError:
                # Can happen on some platforms after local shutdown(SHUT_RD).
                # Treat as alive (send side may still be usable).
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

    # --- Socket operations ------------------------------------------------

    def set_keepalive(self,
                      keep_idle: int | None = None,
                      keep_interval: int | None = None,
                      keep_count: int | None = None):
        """Set TCP keep-alive mode.

        Send a keep-alive ping once every `keep_interval` seconds if activates
        after `keep_idle` seconds of idleness, and closes the connection
        after `keep_count` failed ping.

        Args:
            keep_idle    : Maximum duration to wait before sending keep-alive ping in second.
            keep_interval: Interval to send keep-alive ping in second.
            keep_count   : Maximum number of failed attempts.
        """
        if self._sock is None:
            return

        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if keep_idle is not None:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, keep_idle)
        if keep_interval is not None:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, keep_interval)
        if keep_count is not None:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, keep_count)

    @contextlib.contextmanager
    def out_of_band(self):
        """Send OOB packet in this context.

        Examples:
            .. code-block:: python

                with sock.out_of_band():
                    sock.send(b"XXY")

        Raises:
            AssertionError: If already in OOB context.
        """
        assert not self._oob_flag, "Already in OOB context"

        self._oob_flag = True
        try:
            yield
        finally:
            self._oob_flag = False

    # --- Helpers ----------------------------------------------------------

    @staticmethod
    def _parse_host_port(host: str, port: int | None) -> tuple[str, int]:
        """Normalize various notations into (host, port).
        """
        if port is not None:
            return host.strip(), int(port)

        s = host.strip()
        # 1) tcp:// URI (supports IPv6 in brackets)
        with contextlib.suppress(Exception):
            u = urlparse(s)
            if u.scheme == "tcp" and (u.hostname is not None) and (u.port is not None):
                return u.hostname, int(u.port)

        # 2) [ipv6]:port
        m = re.match(r'^\[(?P<h>[^]]+)\]:(?P<p>\d{1,5})$', s)
        if m:
            return m.group('h'), int(m.group('p'))

        # 3) host:port (avoid raw IPv6 without brackets)
        #    Accept exactly one ':' so we don't collide with IPv6 literals.
        if s.count(":") == 1:
            h, p = s.rsplit(":", 1)
            if p.isdigit():
                return h, int(p)

        # 4) netcat-like: nc|ncat|netcat [opts...] host port
        toks = []
        try:
            toks = shlex.split(s)
        except ValueError:
            toks = s.split()

        if toks:
            cmd = toks[0].lower()
            if cmd in ("nc", "ncat", "netcat", "telnet"):
                args = [t for t in toks[1:] if not t.startswith("-")]
                if len(args) >= 2 and args[-1].isdigit():
                    h = args[-2]
                    # strip brackets if present (IPv6)
                    if h.startswith("[") and h.endswith("]"):
                        h = h[1:-1]
                    return h, int(args[-1])

        # 5) (optional) "host port" without nc; support as a convenience
        if len(toks) >= 2 and toks[-1].isdigit():
            h = toks[-2]
            if h.startswith("[") and h.endswith("]"):
                h = h[1:-1]
            return h, int(toks[-1])

        # If we get here, we couldn't extract a port.
        raise ValueError(f"Could not determine host and port from: {host!r}")

__all__ = ['Socket']
