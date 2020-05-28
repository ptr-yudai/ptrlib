import unittest
import os
from ptrlib import Process
from logging import getLogger, FATAL

class TestProcess(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_process(self):
        while True:
            msg = os.urandom(16)
            if b'\n' not in msg:
                break
        sock = Process("/bin/cat")

        # send / recv
        sock.sendline(b"Message : " + msg)
        self.assertEqual(sock.recvlineafter(" : "), msg)

        # shutdown
        sock.send(msg[::-1])
        sock.shutdown('write')
        self.assertEqual(sock.recvonce(len(msg)), msg[::-1])

if __name__ == '__main__':
    unittest.main()
