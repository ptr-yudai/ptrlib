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
        p = Process("./test/pwn/testbin/test_echo.x64")

        # send / recv
        p.sendline(b"Message : " + msg)
        self.assertEqual(p.recvlineafter(" : "), msg)

        # shutdown
        p.send(msg[::-1])
        p.shutdown('write')
        self.assertEqual(p.recvonce(len(msg)), msg[::-1])

        p.close()

if __name__ == '__main__':
    unittest.main()
