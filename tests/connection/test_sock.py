import unittest
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
        try:
            sock.recvuntil("*** never expected ***", timeout=1)
            result = False
        except TimeoutError as err:
            self.assertEqual(b"200 OK" in err.args[1], True)
            result = True
        except:
            result = False
        finally:
            sock.close()

        self.assertEqual(result, True)
