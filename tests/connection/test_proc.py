"""This package provides some tests for Process feature.
"""
import inspect
import os
import random
import unittest
from logging import FATAL, getLogger

from ptrlib import Process, is_scanf_safe

_is_windows = os.name == 'nt'


class TestProcess(unittest.TestCase):
    """Tests for Process
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if _is_windows:
            self.skipTest("This test is intended for the Linux platform")

    def test_basic(self):
        """Basic tests
        """
        mod = inspect.getmodule(Process)
        assert mod is not None
        module_name = mod.__name__

        while True:
            msg = os.urandom(16)
            if is_scanf_safe(msg):
                break

        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_echo.x64")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                         f'INFO:{module_name}:Successfully created a new process {str(p)}')

        # sendline / recvline
        p.sendline(b"Message : " + msg)
        self.assertEqual(p.recvlineafter(" : "), msg)

        # batch send
        p.sendline([b"A", 3.14, msg, 0xdeadbeef])
        self.assertEqual(p.recvline(), b"A")
        self.assertEqual(p.recvline(), b"3.14")
        self.assertEqual(p.recvline(), msg)
        self.assertEqual(p.recvline(), str(0xdeadbeef).encode())

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
        p.sendline(f"Hello 0x{a:08x}, 0x{b:08x}")
        r = p.recvregex("0x([0-9a-f]+), 0x([0-9a-f]+)")
        p.recvline()
        self.assertEqual(int(r[1], 16), a)
        self.assertEqual(int(r[2], 16), b)

        # sendlineafter
        a, b = os.urandom(16).hex(), os.urandom(16).hex()
        p.sendline(a)
        v = p.sendlineafter(a + "\n", b)
        self.assertEqual(v.strip(), a.encode())
        self.assertEqual(p.recvline().strip(), b.encode())

        # shutdown
        p.send(msg[::-1])
        p.shutdown('send')
        self.assertEqual(p.recvonce(len(msg)), msg[::-1])

        # wait
        self.assertEqual(p.wait(), 0)

        with self.assertLogs(module_name) as cm:
            p.close()
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                         f'INFO:{module_name}:{str(p)} stopped with exit code 0')

    def test_timeout(self):
        """Timeout tests
        """
        mod = inspect.getmodule(Process)
        assert mod is not None
        module_name = mod.__name__

        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_echo.x64")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                         f'INFO:{module_name}:Successfully created a new process {str(p)}')
        data = os.urandom(16).hex()

        # recv
        with self.assertRaises(TimeoutError) as cm:
            p.recv(timeout=0.5)
        self.assertEqual(cm.exception.args[1], b"")

        # recvonce
        p.sendline(data)
        with self.assertRaises(TimeoutError) as cm:
            p.recvonce(len(data) + 1 + 1, timeout=0.5)
        self.assertEqual(cm.exception.args[1].decode().strip(), data)

        # recvuntil
        p.sendline(data)
        with self.assertRaises(TimeoutError) as cm:
            p.recvuntil("*** never expected ***", timeout=0.5)
        self.assertEqual(cm.exception.args[1].decode().strip(), data)

        # sendlineafter
        a, b = os.urandom(16).hex(), os.urandom(16).hex()
        p.sendline(a)
        with self.assertRaises(TimeoutError) as cm:
            p.sendlineafter(b"neko", b, timeout=0.5)
        self.assertEqual(cm.exception.args[1].decode().strip(), a)
