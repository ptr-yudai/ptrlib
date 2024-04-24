import inspect
import os
import random
import subprocess
import unittest
from logging import FATAL, getLogger

from ptrlib import Process, is_scanf_safe

_is_windows = os.name == 'nt'


class TestWinProcess(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if not _is_windows:
            self.skipTest("This test is for Windows architecture")

    def test_basic(self):
        module_name = inspect.getmodule(Process).__name__

        while True:
            msg = os.urandom(16)
            if is_scanf_safe(msg) and b'\x1a' not in msg:
                break

        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_echo.pe.exe")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0], f'INFO:{module_name}:Successfully created new process {str(p)}')
        pid = p.pid

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
        self.assertFalse(str(pid) in subprocess.getoutput(f'tasklist /FI "PID eq {pid}"').split())

    def test_timeout(self):
        module_name = inspect.getmodule(Process).__name__

        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_echo.pe.exe")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0], f'INFO:{module_name}:Successfully created new process {str(p)}')

        with self.assertRaises(TimeoutError):
            p.recvuntil("*** never expected ***", timeout=1)
        p.close()
