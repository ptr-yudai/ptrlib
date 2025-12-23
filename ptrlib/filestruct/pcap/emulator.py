"""Pcap emulator for TCP/UDP communication
"""
import contextlib
import pathlib
import socket
import struct
import time
import typing


def _checksum(data: bytes) -> int:
    """RFC1071
    """
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s = (s + w) & 0xFFFFFFFF
    # fold
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def _pack_pcap_global_header(linktype: int = 1, snaplen: int = 65535) -> bytes:
    # libpcap (microsecond) little-endian
    magic = 0xA1B2C3D4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    return struct.pack(
        "<IHHiiii",
        magic, version_major, version_minor,
        thiszone, sigfigs, snaplen, linktype,
    )

def _pack_pcap_packet_header(ts: float, caplen: int, length: int) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, caplen, length)

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

def _eth_header(src_mac: bytes, dst_mac: bytes, ethertype: int) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype)

def _ipv4_header(src_ip: str,
                 dst_ip: str,
                 payload_len: int,
                 proto: int,
                 ident: int,
                 ttl: int = 64,
                 df: bool = True) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0x4000 if df else 0
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident,
        flags_frag, ttl, proto, checksum,
        src, dst,
    )
    checksum = _checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident,
        flags_frag, ttl, proto, checksum,
        src, dst,
    )
    return header

def _ipv6_header(src_ip: str,
                 dst_ip: str,
                 payload_len: int,
                 nexthdr: int,
                 hop_limit: int = 64,
                 traffic_class: int = 0,
                 flow_label: int = 0) -> bytes:
    vtc_fl = (6 << 28) | ((traffic_class & 0xFF) << 20) | (flow_label & 0xFFFFF)
    src = socket.inet_pton(socket.AF_INET6, src_ip)
    dst = socket.inet_pton(socket.AF_INET6, dst_ip)
    return struct.pack("!IHBB16s16s", vtc_fl, payload_len, nexthdr, hop_limit, src, dst)

def _tcp_header_v6(src_ip: str,
                   dst_ip: str,
                   src_port: int,
                   dst_port: int,
                   seq: int,
                   ack: int,
                   flags: int,
                   window: int,
                   payload: bytes,
                   options: bytes = b"") -> bytes:
    data_offset_words = 5 + (len(options) + 3) // 4
    offset_flags = (data_offset_words << 12) | (flags & 0x01FF)
    urg_ptr = 0
    checksum = 0
    base = struct.pack(
        "!HHIIHHHH",
        src_port, dst_port, seq, ack,
        offset_flags, window, checksum, urg_ptr
    )
    if options:
        pad = (4 - (len(options) % 4)) % 4
        base += options + (b"\x00" * pad)
    pseudo  = socket.inet_pton(socket.AF_INET6, src_ip) + socket.inet_pton(socket.AF_INET6, dst_ip)
    pseudo += struct.pack("!I3xB", len(base) + len(payload), IP_PROTO_TCP)
    checksum = _checksum(pseudo + base + payload)
    base = base[:16] + struct.pack("!H", checksum) + base[18:]
    return base

def _udp_header_v6(src_ip: str,
                   dst_ip: str,
                   src_port: int,
                   dst_port: int,
                   payload: bytes) -> bytes:
    length = 8 + len(payload)
    checksum = 0
    base = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    pseudo  = socket.inet_pton(socket.AF_INET6, src_ip) + socket.inet_pton(socket.AF_INET6, dst_ip)
    pseudo += struct.pack("!I3xB", length, IP_PROTO_UDP)
    csum = _checksum(pseudo + base + payload)
    if csum == 0:
        # For IPv6, checksum must not be zero; represent zero as 0xFFFF
        csum = 0xFFFF
    base = struct.pack("!HHHH", src_port, dst_port, length, csum)
    return base

def _tcp_header(src_ip: str,
                dst_ip: str,
                src_port: int,
                dst_port: int,
                seq: int,
                ack: int,
                flags: int,
                window: int,
                payload: bytes,
                options: bytes = b"") -> bytes:
    data_offset_words = 5 + (len(options) + 3) // 4
    offset_flags = (data_offset_words << 12) | (flags & 0x01FF)
    urg_ptr = 0
    checksum = 0
    base = struct.pack(
        "!HHIIHHHH",
        src_port, dst_port, seq, ack,
        offset_flags, window, checksum, urg_ptr
    )
    # pad options to 32bit
    if options:
        pad = (4 - (len(options) % 4)) % 4
        base += options + (b"\x00" * pad)
    pseudo  = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    pseudo += struct.pack("!BBH", 0, IP_PROTO_TCP, len(base) + len(payload))
    checksum = _checksum(pseudo + base + payload)
    base = base[:16] + struct.pack("!H", checksum) + base[18:]
    return base

def _udp_header(src_ip: str,
                dst_ip: str,
                src_port: int,
                dst_port: int,
                payload: bytes) -> bytes:
    length = 8 + len(payload)
    checksum = 0
    base = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    pseudo  = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    pseudo += struct.pack("!BBH", 0, IP_PROTO_UDP, length)
    csum = _checksum(pseudo + base + payload)
    if csum == 0:
        # Checksum 0 means "unused" in IPv4 UDP but some implementations expect 0xFFFF
        csum = 0xFFFF
    base = struct.pack("!HHHH", src_port, dst_port, length, csum)
    return base


class PcapFile:
    """Helper class to write 1-to-1 pseudo sessions to pcap.

    Parameters:
        path (str): Output pcap file path.
        udp (bool): True if UDP, False if TCP.
        local (str): Local IP address (default: 127.0.0.1).
        remote (str): Remote IP address/hostname (resolved automatically if needed).
        local_port (int): Local port number (default: 50000).
        remote_port (int): Remote port number (default: 80 for TCP, 53 for UDP).
        auto_ack (bool): Generate ACK-only packets for the reverse direction on data send/receive.
        mss (int): Maximum segment size for TCP (default: 1460).
        linktype_eth (bool): True if Ethernet frame (DLT_EN10MB). Currently, only True is supported.
        ts_base (float): Base timestamp (default: None).
    """
    def __init__(
        self,
        path: str | pathlib.Path,
        *,
        udp: bool = False,
        local: str = "127.0.0.1",
        remote: str = "0.0.0.0",
        local_port: int = 31337,
        remote_port: int = 1337,
        auto_ack: bool = True,
        mss: int = 1460,
        linktype_eth: bool = True,
        ts_base: float | None = None,
    ) -> None:
        self._remote_raw = "127.0.0.1"

        self.path = path
        self.udp = udp
        self.local: str = local
        # Predeclare for type-checkers; set properly in remote setter below
        self.remote_ip: str = ""
        self.remote = remote
        self.local_port = local_port
        self.remote_port = remote_port
        self.auto_ack = auto_ack
        self.mss = int(mss)
        self.linktype_eth = linktype_eth
        self.ts_base = ts_base or time.time()
        self._last_ts = self.ts_base
        # Address family for IP header emission (default IPv4; may switch to IPv6 via remote setter)
        self._af = socket.AF_INET

        if self.local == self.remote_ip and self.local_port == self.remote_port:
            raise ValueError("IP address and port number for local/remote are identical.")

        # Ethernet MAC
        self.local_mac = b"\x00\x00\x5e\x00\x53\x00"
        self.remote_mac = b"\x00\x00\x5e\x00\x53\xff"

        # IPv4 ID counter
        self._ip_id = 0 # random

        # TCP state
        self._tcp_connected = False
        self._lseq = 0 # random
        self._rseq = 0 # random
        self._lack = 0
        self._rack = 0
        self._lfin = False
        self._rfin = False

        # Output file handle
        self._fh: typing.BinaryIO | None = open(self.path, "wb")
        self._fh.write(_pack_pcap_global_header(linktype=1, snaplen=65535))
        self._fh.flush()

    def __del__(self):
        self.close()

    @property
    def remote(self) -> str:
        """Remote IP address.
        """
        return self._remote_raw

    @remote.setter
    def remote(self, value: str) -> None:
        self._remote_raw = value
        try:
            infos = socket.getaddrinfo(value, None, socket.AF_UNSPEC, 0, 0, 0)
            # Prefer IPv6 if available, otherwise take the first entry
            chosen = None
            for ai in infos:
                if ai[0] == socket.AF_INET6:
                    chosen = ai
                    break
            if chosen is None:
                chosen = infos[0]
            af = chosen[0]
            ip_obj = chosen[4][0]
            ip: str = ip_obj if isinstance(ip_obj, str) else str(ip_obj)
            self.remote_ip = ip
            self._af = af
        except socket.gaierror:
            # Fallback: keep the raw value and guess family from format
            self.remote_ip = value
            self._af = socket.AF_INET6 if (":" in value and not value.count(".")) else socket.AF_INET

        # If remote is IPv6 and local is the default IPv4, switch to loopback v6
        if self._af == socket.AF_INET6 and self.local == "127.0.0.1":
            self.local = "::1"

    def connect(self, ts: float | None = None) -> None:
        """TCP: Generate 3-way handshake.
        """
        if self.udp or self._tcp_connected:
            return
        base_ts = self._now(ts)
        eps = 0.0001
        # SYN (L->R)
        self._tcp_send(flags=TCP_SYN, ts=base_ts)
        # SYN-ACK (R->L)
        self._tcp_recv(flags=TCP_SYN | TCP_ACK, ts=base_ts + eps)
        # ACK (L->R)
        self._tcp_send(flags=TCP_ACK, ts=base_ts + 2 * eps)
        self._tcp_connected = True

    def send(self, data: bytes, ts: float | None = None) -> None:
        """Send data from local to remote.

        Long data is segmented into MSS-sized chunks.
        """
        if not self.udp and not self._tcp_connected:
            self.connect(ts)

        for chunk, t in self._segment(data, ts):
            if self.udp:
                self._udp_send(chunk, ts=t)
            else:
                self._tcp_send(payload=chunk, flags=TCP_PSH | TCP_ACK, ts=t)
                if self.auto_ack:
                    self._tcp_recv(flags=TCP_ACK, ts=t + 0.00005)

    def recv(self, data: bytes, ts: float | None = None) -> None:
        """Receive data from remote to local (i.e., synthesize data sent from the other party).
        """
        if not self.udp and not self._tcp_connected:
            self.connect(ts)
        for chunk, t in self._segment(data, ts):
            if self.udp:
                self._udp_recv(chunk, ts=t)
            else:
                self._tcp_recv(payload=chunk, flags=TCP_PSH | TCP_ACK, ts=t)
                if self.auto_ack:
                    self._tcp_send(flags=TCP_ACK, ts=t + 0.00005)

    def close_send(self, ts: float | None = None) -> None:
        """Send FIN from local to remote (TCP only).
        """
        if self.udp or self._lfin:
            return
        if not self._tcp_connected:
            self.connect(ts)
        t = self._now(ts)
        self._tcp_send(flags=TCP_FIN | TCP_ACK, ts=t)
        self._lfin = True
        if self.auto_ack:
            self._tcp_recv(flags=TCP_ACK, ts=t + 0.00005)

    def close(self, ts: float | None = None) -> None:
        """Close the session. If TCP, send FIN from both sides.
        """
        try:
            if self.udp:
                # UDP: Do nothing
                self.flush()
                return

            # Do nothing if not connected
            if not self._tcp_connected:
                return

            now = self._now(ts)
            eps = 0.0001

            if not self._lfin:
                self._tcp_send(flags=TCP_FIN | TCP_ACK, ts=now)
                self._lfin = True
                if self.auto_ack:
                    self._tcp_recv(flags=TCP_ACK, ts=now + eps)
                now += 2 * eps

            if not self._rfin:
                self._tcp_recv(flags=TCP_FIN | TCP_ACK, ts=now)
                self._rfin = True
                self._tcp_send(flags=TCP_ACK, ts=now + eps)

            self.flush()

        finally:
            if self._fh is not None:
                # Best-effort close: pcap logging must not break application logic.
                # In some environments (e.g. during heavy mocking), the underlying
                # file descriptor can become invalid unexpectedly.
                with contextlib.suppress(Exception):
                    self._fh.close()
                self._fh = None

    def advance(self, seconds: float) -> None:
        """Advance the internal clock by a specified number of seconds.
        """
        self._last_ts += float(seconds)

    def flush(self) -> None:
        """Flush the file handle and synchronize the file system.
        
        Best-effort: errors are suppressed so pcap logging never breaks
        application logic (e.g., when the FD has been invalidated by the
        environment/tests).
        """
        if self._fh is None:
            return
        with contextlib.suppress(Exception):
            self._fh.flush()

    def __enter__(self) -> "PcapFile":
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        with contextlib.suppress(Exception):
            self.close()

    def _segment(self, data: bytes, ts: float | None):
        if self.udp or len(data) <= self.mss:
            yield data, self._now(ts)
            return

        # Split
        pos = 0
        t = self._now(ts)
        eps = 0.00002
        while pos < len(data):
            chunk = data[pos : pos + self.mss]
            yield chunk, t
            pos += len(chunk)
            t += eps

    def _tcp_send(self, *, payload: bytes = b"", flags: int, ts: float) -> None:
        seq = self._lseq
        ack = self._rseq if (flags & TCP_ACK) else 0
        self._emit_tcp(self.local, self.remote_ip,
                       self.local_port, self.remote_port,
                       seq, ack, flags, payload, ts, dir_out=True)
        if flags & TCP_SYN:
            self._lseq = (self._lseq + 1) & 0xFFFFFFFF
        if flags & TCP_FIN:
            self._lseq = (self._lseq + 1) & 0xFFFFFFFF
        if payload:
            self._lseq = (self._lseq + len(payload)) & 0xFFFFFFFF

    def _tcp_recv(self, *, payload: bytes = b"", flags: int, ts: float) -> None:
        seq = self._rseq
        ack = self._lseq if (flags & TCP_ACK) else 0
        self._emit_tcp(self.remote_ip, self.local,
                       self.remote_port, self.local_port,
                       seq, ack, flags, payload, ts, dir_out=False)
        if flags & TCP_SYN:
            self._rseq = (self._rseq + 1) & 0xFFFFFFFF
            self._rack = (self._lseq) & 0xFFFFFFFF
            self._lack = (self._rseq) & 0xFFFFFFFF
        if flags & TCP_FIN:
            self._rseq = (self._rseq + 1) & 0xFFFFFFFF
        if payload:
            self._rseq = (self._rseq + len(payload)) & 0xFFFFFFFF
            self._lack = self._rseq

    def _udp_send(self, payload: bytes, ts: float) -> None:
        self._emit_udp(self.local, self.remote_ip,
                       self.local_port, self.remote_port,
                       payload, ts, dir_out=True)

    def _udp_recv(self, payload: bytes, ts: float) -> None:
        self._emit_udp(self.remote_ip, self.local,
                       self.remote_port, self.local_port,
                       payload, ts, dir_out=False)

    def _emit_tcp(self,
                  sip: str,
                  dip: str,
                  sport: int,
                  dport: int,
                  seq: int,
                  ack: int,
                  flags: int,
                  payload: bytes,
                  ts: float,
                  *,
                  dir_out: bool) -> None:
        options = b""
        if self._af == socket.AF_INET6:
            tcp = _tcp_header_v6(sip, dip, sport, dport,
                                 seq, ack, flags, window=65535,
                                 payload=payload, options=options)
            ip = _ipv6_header(sip, dip, payload_len=len(tcp) + len(payload),
                              nexthdr=IP_PROTO_TCP)
            eth = _eth_header(self.local_mac if dir_out else self.remote_mac,
                              self.remote_mac if dir_out else self.local_mac, ETH_P_IPV6)
        else:
            tcp = _tcp_header(sip, dip, sport, dport,
                              seq, ack, flags, window=65535,
                              payload=payload, options=options)
            ip = _ipv4_header(sip, dip, payload_len=len(tcp) + len(payload),
                              proto=IP_PROTO_TCP, ident=self._alloc_ip_id())
            eth = _eth_header(self.local_mac if dir_out else self.remote_mac,
                              self.remote_mac if dir_out else self.local_mac, ETH_P_IP)
        frame = eth + ip + tcp + payload
        self._write(ts, frame)

    def _emit_udp(self,
                  sip: str,
                  dip: str,
                  sport: int,
                  dport: int,
                  payload: bytes,
                  ts: float,
                  *,
                  dir_out: bool) -> None:
        if self._af == socket.AF_INET6:
            udp = _udp_header_v6(sip, dip, sport, dport, payload)
            ip = _ipv6_header(sip, dip, payload_len=len(udp) + len(payload),
                              nexthdr=IP_PROTO_UDP)
            eth = _eth_header(self.local_mac if dir_out else self.remote_mac,
                              self.remote_mac if dir_out else self.local_mac, ETH_P_IPV6)
        else:
            udp = _udp_header(sip, dip, sport, dport, payload)
            ip = _ipv4_header(sip, dip, payload_len=len(udp) + len(payload),
                              proto=IP_PROTO_UDP, ident=self._alloc_ip_id())
            eth = _eth_header(self.local_mac if dir_out else self.remote_mac,
                              self.remote_mac if dir_out else self.local_mac, ETH_P_IP)
        frame = eth + ip + udp + payload
        self._write(ts, frame)

    def _write(self, ts: float, frame: bytes) -> None:
        """Best-effort writer; swallow I/O errors to avoid affecting callers.
        
        In some environments, file descriptors may get closed or invalidated
        unexpectedly (e.g., heavy mocking, embedded REPLs). Any error during
        pcap emission is suppressed and the pcap stream is disabled.
        """
        fh = self._fh
        if fh is None:
            return
        try:
            if ts <= self._last_ts:
                ts = self._last_ts + 0.000001
            self._last_ts = ts
            hdr = _pack_pcap_packet_header(ts, len(frame), len(frame))
            fh.write(hdr)
            fh.write(frame)
            fh.flush()
        except Exception:
            # Disable further logging on any failure
            with contextlib.suppress(Exception):
                fh.close()
            self._fh = None

    def _alloc_ip_id(self) -> int:
        self._ip_id = (self._ip_id + 1) & 0xFFFF
        return self._ip_id

    def _now(self, ts: float | None) -> float:
        return float(ts) if ts is not None else time.time()


__all__ = ['PcapFile']

if __name__ == "__main__":
    with PcapFile("demo_tcp.pcap",
                  local="10.0.0.1", remote="10.0.0.2",
                  local_port=40000, remote_port=2222) as pcap:
        pcap.send(b"What is your name?\n")
        pcap.recv(b"Thomas")
        pcap.recv(b" Brown")
        pcap.close_send()
    with PcapFile("demo_udp.pcap", udp=True,
                  local="10.0.0.1", remote="10.0.0.2",
                  local_port=50000, remote_port=50001) as pcap:
        pcap.send(b"ping")
        pcap.recv(b"pong")
