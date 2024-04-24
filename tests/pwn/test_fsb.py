import inspect
import os
import unittest
from logging import FATAL, getLogger

from ptrlib import Process, fsb

_is_windows = os.name == 'nt'


class TestFSB(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if _is_windows:
            # TODO: Implement test for Windows
            self.skipTest("This test has not been implemented for Windows yet")

    def test_fsb32(self):
        module_name = inspect.getmodule(Process).__name__

        # test 1
        for i in range(3):
            with self.assertLogs(module_name) as cm:
                p = Process("./tests/test.bin/test_fsb.x86")
            self.assertEqual(len(cm.output), 1)
            self.assertEqual(cm.output[0], f'INFO:{module_name}:Successfully created new process {str(p)}')
            p.recvuntil(": ")
            target = int(p.recvline(), 16)
            payload = fsb(
                pos = 4,
                writes = {target: 0xdeadbeef},
                bs = 1,
                bits = 32
            )
            p.sendline(payload + b'XXXXXXXX')
            p.recvuntil("XXXXXXXX\n")
            self.assertTrue(b'OK' in p.recvline())
            p.close()

        # test 2
        for i in range(3):
            with self.assertLogs(module_name) as cm:
                p = Process("./tests/test.bin/test_fsb.x86")
            self.assertEqual(len(cm.output), 1)
            self.assertEqual(cm.output[0], f'INFO:{module_name}:Successfully created new process {str(p)}')
            p.recvuntil(": ")
            target = int(p.recvline(), 16)
            payload = fsb(
                pos = 4,
                writes = {target: 0xdeadbeef},
                bs = 1,
                bits = 32,
                rear = True
            )
            p.sendline(payload + b'XXXXXXXX')
            p.recvuntil("XXXXXXXX\n")
            self.assertTrue(b'OK' in p.recvline())
            p.close()

    def test_fsb64(self):
        module_name = inspect.getmodule(Process).__name__

        # test 3
        for i in range(3):
            with self.assertLogs(module_name) as cm:
                p = Process("./tests/test.bin/test_fsb.x64")
            self.assertEqual(len(cm.output), 1)
            self.assertEqual(cm.output[0], f'INFO:{module_name}:Successfully created new process {str(p)}')
            p.recvuntil(": ")
            target = int(p.recvline(), 16)
            payload = fsb(
                pos = 6,
                writes = {target: 0xdeadbeef},
                bs = 1,
                bits = 64
            )
            p.sendline(payload)
            self.assertTrue(b'OK' in p.recvuntil("OK"))
            p.close()
