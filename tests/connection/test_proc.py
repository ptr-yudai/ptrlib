import unittest
import os
import random
from ptrlib import Process, is_scanf_safe
from logging import getLogger, FATAL


class TestProcess(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_basic(self):
        while True:
            msg = os.urandom(16)
            if is_scanf_safe(msg):
                break

        p = Process("./tests/test.bin/test_echo.x64")

        # send / recv
        p.sendline(b"Message : " + msg)
        self.assertEqual(p.recvlineafter(" : "), msg)

        # send / recvuntil
        for _ in range(10):
            a, b = os.urandom(16).hex(), os.urandom(16).hex()
            is_a = random.randint(0, 1)
            p.sendline(a if is_a else b)
            c = p.recvuntil([a, b.encode()]) # recv either of them
            if is_a:
                self.assertEqual(c, a.encode())
            else:
                self.assertEqual(c, b.encode())
            p.recvline()

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

        # wait
        self.assertEqual(p.wait(), 0)

        p.close()

    def test_timeout(self):
        p = Process("./tests/test.bin/test_echo.x64")
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
