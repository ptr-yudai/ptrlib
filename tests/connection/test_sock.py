import inspect
import json
import unittest
from logging import getLogger, FATAL
from socket import gethostbyname
from ptrlib import Socket, TubeTimeout


class TestSocket(unittest.TestCase):
    """Tests for Socket
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_socket(self):
        """Test socket connection and data exchange.
        """
        # connect
        sock = Socket("www.example.com", 80)

        # request 
        sock.sendline(b'GET / HTTP/1.1\r')
        sock.send(b'Host: www.example.com\r\n\r\n')

        # shutdown
        sock.close_send()

        # receive
        result = int(sock.recvlineafter('Content-Length: ')) > 0
        sock.close()

        self.assertEqual(result, True)

    def test_timeout(self):
        """Test socket timeout behavior.
        """
        mod = inspect.getmodule(Socket)
        assert mod is not None
        module_name = mod.__name__

        sock = Socket("www.example.com", 80)
        sock.sendline(b'GET / HTTP/1.1\r')
        sock.send(b'Host: www.example.com\r\n\r\n')

        with self.assertRaises(TubeTimeout) as cm:
            sock.recvuntil("*** never expected ***", timeout=2)
        self.assertEqual(b"200 OK" in cm.exception.buffered, True)

        with self.assertLogs(module_name) as cm:
            sock.close()
        self.assertEqual(cm.output, [f"INFO:{module_name}:Connection {str(sock)} closed"])

    def test_reset(self):
        """Test socket connection reset behavior.
        """
        sock = Socket("www.example.com", 80)
        sock.sendline(b'GET / HTTP/1.1\r')
        sock.send(b'Host: www.example.com\r\n')
        sock.send(b'Connection: close\r\n\r\n')

        with self.assertRaises(EOFError):
            sock.recvuntil("*** never expected ***", timeout=2)

        sock.close()

    def test_tls(self):
        """Test socket TLS behavior.
        """
        host = "check-tls.akamaized.net"
        path = "/v1/tlssni.json"

        # connect with SNI enabled
        sock = Socket(host, 443, ssl=True)
        sock.sendline(f'GET {path} HTTP/1.1'.encode() + b'\r')
        sock.send(f'Host: {host}'.encode() + b'\r\n')
        sock.send(b'Connection: close\r\n\r\n')
        self.assertTrue((contentlength := int(sock.recvlineafter('Content-Length: '))) > 0)
        sock.recvuntil(b'\r\n\r\n')
        content = json.loads(sock.recvall(contentlength))
        sock.close()
        self.assertEqual(content['tls_sni_status'], "present")
        self.assertEqual(content['tls_sni_value'], host)

        # connect with a specific SNI value
        ip_addr = gethostbyname(host)
        sock = Socket(ip_addr, 443, ssl=True, sni="akamaized.net")
        sock.sendline(f'GET {path} HTTP/1.1'.encode() + b'\r')
        sock.send(f'Host: {host}'.encode() + b'\r\n')
        sock.send(b'Connection: close\r\n\r\n')
        self.assertTrue((contentlength := int(sock.recvlineafter('Content-Length: '))) > 0)
        sock.recvuntil(b'\r\n\r\n')
        content = json.loads(sock.recvall(contentlength))
        sock.close()
        self.assertEqual(content['tls_sni_status'], "invalid")
        self.assertEqual(content['tls_sni_value'], "akamaized.net")

        # connect with SNI disabled
        sock = Socket(host, 443, ssl=True, sni=False)
        sock.sendline(f'GET {path} HTTP/1.1'.encode() + b'\r')
        sock.send(f'Host: {host}'.encode() + b'\r\n')
        sock.send(b'Connection: close\r\n\r\n')
        self.assertTrue((contentlength := int(sock.recvlineafter('Content-Length: '))) > 0)
        sock.recvuntil(b'\r\n\r\n')
        content = json.loads(sock.recvall(contentlength))
        sock.close()
        self.assertEqual(content['tls_sni_status'], "missing")
        self.assertEqual(content['tls_sni_value'], "")
