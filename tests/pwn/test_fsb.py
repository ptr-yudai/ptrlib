"""This package provides some tests for SROP feature.
"""
import inspect
import os
import random
import unittest
from logging import FATAL, getLogger

from ptrlib import Process, FSB, p8, p16, p32, p64

_is_windows = os.name == 'nt'


class TestFSB(unittest.TestCase):
    """Tests for FSB class.
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if _is_windows:
            self.skipTest("This test has not been implemented for Windows yet")

    def test_fsb32(self):
        """Tests for 32-bit FSB
        """
        module_name = inspect.getmodule(Process).__name__

        # Test 1
        for _ in range(3):
            with self.assertLogs(module_name) as cm:
                p = Process("./tests/test.bin/test_fsb.x86")
            self.assertEqual(len(cm.output), 1)
            self.assertEqual(cm.output[0],
                             f'INFO:{module_name}:Successfully created a new process {str(p)}')
            p.recvuntil(": ")
            target = int(p.recvline(), 16)

            fsb = FSB(4, bits=32)
            fsb.write(target, p32(0xdeadbeef))
            p.sendline(fsb.payload + b'XXXXXXXX')
            p.recvuntil("XXXXXXXX\n")
            self.assertTrue(b'OK' in p.recvline())
            p.close()

        # Test 2
        for _ in range(3):
            with self.assertLogs(module_name) as cm:
                p = Process("./tests/test.bin/test_fsb.x86")
            self.assertEqual(len(cm.output), 1)
            self.assertEqual(cm.output[0],
                             f'INFO:{module_name}:Successfully created a new process {str(p)}')
            p.recvuntil(": ")
            target = int(p.recvline(), 16)

            fsb = FSB(4, bits=32)
            fsb.rear = True
            fsb.write(target, p8(0xef))
            fsb.write(target+1, p16(0xadbe), 2)
            fsb.write(target+3, p8(0xde))
            p.sendline(fsb.payload + b'XXXXXXXX')
            p.recvuntil("XXXXXXXX\n")
            self.assertTrue(b'OK' in p.recvline())
            p.close()

    def test_fsb32_read(self):
        """Tests for 32-bit FSB read
        """
        module_name = inspect.getmodule(Process).__name__

        # Test 1
        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_fsb.x86")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                            f'INFO:{module_name}:Successfully created a new process {str(p)}')
        p.recvuntil(": ")
        target = int(p.recvline(), 16)

        fsb = FSB(4, bits=32)
        fsb.read(target - 0xed8, len("/lib/ld-linux.so.2"))
        fsb.write(target, p32(0xdeadbeef))
        p.sendline(fsb.payload + b'XXXXXXXX')
        self.assertTrue(b'/lib/ld-linux.so.2' in p.recvuntil("XXXXXXXX\n"))
        self.assertTrue(b'OK' in p.recvline())
        p.close()

        # Test 2
        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_fsb.x86")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                            f'INFO:{module_name}:Successfully created a new process {str(p)}')
        p.recvuntil(": ")
        target = int(p.recvline(), 16)

        fsb = FSB(4, bits=32)
        fsb.rear = True
        fsb.write(target, p8(0xef))
        fsb.read(target - 0xed8, len("/lib/ld-linux.so.2"))
        fsb.write(target+1, p16(0xadbe), 2)
        fsb.write(target+3, p8(0xde))
        p.sendline(fsb.payload + b'XXXXXXXX')
        self.assertTrue(b'/lib/ld-linux.so.2' in p.recvuntil("XXXXXXXX\n"))
        self.assertTrue(b'OK' in p.recvline())
        p.close()

    def test_fsb32_print(self):
        """Tests for 32-bit FSB read
        """
        module_name = inspect.getmodule(Process).__name__

        # Test 1
        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_fsb.x86")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                            f'INFO:{module_name}:Successfully created a new process {str(p)}')
        p.recvuntil(": ")
        target = int(p.recvline(), 16)

        fsb = FSB(4, bits=32)
        data = b'A' * random.randint(1, 7)
        fsb.print(data)
        fsb.read(target - 0xed8, len("/lib/ld-linux.so.2"))
        fsb.print(data)
        fsb.read(target - 0xed8, len("/lib/ld-linux.so.2"))
        fsb.print(data)
        fsb.read(target - 0xed8, len("/lib/ld-linux.so.2"))
        fsb.write(target, p32(0xdeadbeef))
        p.sendline(fsb.payload + b'XXXXXXXX')

        expected = (data + b"/lib/ld-linux.so.2") * 3
        self.assertTrue(expected in p.recvuntil("XXXXXXXX\n"))
        self.assertTrue(b'OK' in p.recvline())
        p.close()

    def test_fsb64(self):
        """Tests for 64-bit FSB
        """
        module_name = inspect.getmodule(Process).__name__

        # Test 1
        for _ in range(3):
            with self.assertLogs(module_name) as cm:
                p = Process("./tests/test.bin/test_fsb.x64")
            self.assertEqual(len(cm.output), 1)
            self.assertEqual(cm.output[0],
                             f'INFO:{module_name}:Successfully created a new process {str(p)}')
            p.recvuntil(": ")
            target = int(p.recvline(), 16)

            fsb = FSB(6)
            fsb.write(target, p64(0xdeadbeef), 1)
            p.sendline(fsb.payload)
            self.assertTrue(b'OK' in p.recvuntil("OK"))
            p.close()

        # Test 2
        for _ in range(3):
            with self.assertLogs(module_name) as cm:
                p = Process("./tests/test.bin/test_fsb.x64")
            self.assertEqual(len(cm.output), 1)
            self.assertEqual(cm.output[0],
                             f'INFO:{module_name}:Successfully created a new process {str(p)}')
            p.recvuntil(": ")
            target = int(p.recvline(), 16)

            fsb = FSB(6)
            fsb.write(target, p8(0xef), 1)
            fsb.write(target+1, p16(0xadbe), 2)
            fsb.write(target+3, p32(0xde), 2)
            p.sendline(fsb.payload)
            self.assertTrue(b'OK' in p.recvuntil("OK"))
            p.close()

    def test_fsb64_read(self):
        """Tests for 64-bit FSB read
        """
        module_name = inspect.getmodule(Process).__name__

        # Test 1
        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_fsb.x64")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                            f'INFO:{module_name}:Successfully created a new process {str(p)}')
        p.recvuntil(": ")
        target = int(p.recvline(), 16)

        fsb = FSB(6)
        fsb.read(target - 0xe34, len("/lib64/ld-linux-x86-64.so.2"))
        fsb.write(target, p64(0xdeadbeef), 1)
        p.sendline(fsb.payload)
        self.assertTrue(p.recvuntil('OK').startswith(b'/lib64/ld-linux-x86-64.so.2'))
        p.close()

        # Test 2
        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_fsb.x64")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                            f'INFO:{module_name}:Successfully created a new process {str(p)}')
        p.recvuntil(": ")
        target = int(p.recvline(), 16)

        fsb = FSB(6)
        fsb.write(target, p8(0xef), 1)
        fsb.write(target+1, p16(0xadbe), 2)
        fsb.read(target - 0xe34, len("/lib64/ld-linux-x86-64.so.2"))
        fsb.write(target+3, p32(0xde), 2)
        p.sendline(fsb.payload)
        self.assertTrue(b'/lib64/ld-linux-x86-64.so.2' in p.recvuntil('OK'))
        p.close()

    def test_fsb64_print(self):
        """Tests for 64-bit FSB print
        """
        module_name = inspect.getmodule(Process).__name__

        # Test 1
        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_fsb.x64")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                            f'INFO:{module_name}:Successfully created a new process {str(p)}')
        p.recvuntil(": ")
        target = int(p.recvline(), 16)

        fsb = FSB(6)
        data = b"A" * random.randint(1, 7)
        fsb.print(data)
        fsb.read(target - 0xe34, len("/lib64/ld-linux-x86-64.so.2"))
        fsb.print(data)
        fsb.read(target - 0xe34, len("/lib64/ld-linux-x86-64.so.2"))
        fsb.print(data)
        fsb.read(target - 0xe34, len("/lib64/ld-linux-x86-64.so.2"))
        fsb.write(target, p64(0xdeadbeef), 1)
        p.sendline(fsb.payload)
        expected = (data + b'/lib64/ld-linux-x86-64.so.2') * 3
        self.assertTrue(p.recvuntil('OK').startswith(expected))
