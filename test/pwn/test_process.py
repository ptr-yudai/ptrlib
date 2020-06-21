import unittest
import os
import random
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

        # send / recvregex
        a, b = random.randrange(1<<32), random.randrange(1<<32)
        p.sendline("Hello 0x{:08x}, 0x{:08x}".format(a, b))
        r = p.recvregex("0x([0-9a-f]+), 0x([0-9a-f]+)")
        p.recvline()
        self.assertEqual(int(r[0], 16), a)
        self.assertEqual(int(r[1], 16), b)

        # shutdown
        p.send(msg[::-1])
        p.shutdown('write')
        self.assertEqual(p.recvonce(len(msg)), msg[::-1])

        p.close()

if __name__ == '__main__':
    unittest.main()
