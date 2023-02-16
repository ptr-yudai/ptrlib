import unittest
import os
import random
from ptrlib import Process, is_scanf_safe
from logging import getLogger, FATAL

_is_windows = os.name == 'nt'


class TestWinProcess(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if not _is_windows:
            self.skipTest("This test is for Windows architecture")

    def test_basic(self):
        while True:
            msg = os.urandom(16)
            if is_scanf_safe(msg):
                break

        p = Process("./tests/test.bin/test_echo.pe.exe")

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

        self.assertEqual(p.is_alive(), True)
        p.close()
        self.assertEqual(p.is_alive(), False)

    def test_timeout(self):
        p = Process("./tests/test.bin/test_echo.pe.exe")
        try:
            p.recvuntil("*** never expected ***", timeout=1)
            result = False
        except TimeoutError:
            result = True
        except:
            result = False
        finally:
            p.close()

        self.assertEqual(result, True)
