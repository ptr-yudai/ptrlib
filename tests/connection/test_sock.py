import unittest
from socket import gethostbyname
from ptrlib import Socket
from logging import getLogger, FATAL


class TestSocket(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_socket(self):
        # connect
        sock = Socket("www.example.com", 80)

        # request 
        sock.sendline(b'GET / HTTP/1.1\r')
        sock.send(b'Host: www.example.com\r\n\r\n')

        # shutdown
        sock.shutdown('write')

        # receive
        result = int(sock.recvlineafter('Content-Length: ')) > 0
        sock.close()

        self.assertEqual(result, True)

    def test_timeout(self):
        sock = Socket("www.example.com", 80)
        sock.sendline(b'GET / HTTP/1.1\r')
        sock.send(b'Host: www.example.com\r\n\r\n')

        with self.assertRaises(TimeoutError) as cm:
            sock.recvuntil("*** never expected ***", timeout=2)
        self.assertEqual(b"200 OK" in cm.exception.args[1], True)

    def test_reset(self):
        sock = Socket("www.example.com", 80)
        sock.sendline(b'GET / HTTP/1.1\r')
        sock.send(b'Host: www.example.com\r\n')
        sock.send(b'Connection: close\r\n\r\n')

        with self.assertRaises(ConnectionResetError) as cm:
            sock.recvuntil("*** never expected ***", timeout=2)
        self.assertEqual(b"200 OK" in cm.exception.args[1], True)

    def test_tls(self):
        host = "www.example.com"

        # connect with sni
        ip_addr = gethostbyname(host)
        sock = Socket(ip_addr, 443, ssl=True, sni=host)
        sock.sendline(b'GET / HTTP/1.1\r')
        sock.send(b'Host: www.example.com\r\n')
        sock.send(b'Connection: close\r\n\r\n')
        self.assertTrue(int(sock.recvlineafter('Content-Length: ')) > 0)
        sock.close()

        # connect without sni
        sock = Socket(host, 443, ssl=True)
        sock.sendline(b'GET / HTTP/1.1\r')
        sock.send(b'Host: www.example.com\r\n')
        sock.send(b'Connection: close\r\n\r\n')
        self.assertTrue(int(sock.recvlineafter('Content-Length: ')) > 0)
        sock.close()
