import hashlib
import os
import struct
import unittest
from ptrlib.connection.proc import *
from ptrlib.arch.linux.memory import *
from logging import getLogger, FATAL

_is_windows = os.name == 'nt'


class TestLinuxMemory(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if _is_windows:
            self.skipTest("This test is intended for the Linux platform")

    def test_vmmap(self):
        p = Process("./tests/test.bin/fastexit.x64")
        
        known_mem = [
            (0x400000, 0x401000, 0x0000, "r--p", "fastexit.x64"),
            (0x401000, 0x40b000, 0x1000, "r-xp", "fastexit.x64"),
            (0x40b000, 0x40d000, 0xb000, "r--p", "fastexit.x64"),
            (0x40d000, 0x40f000, 0xc000, "rw-p", "fastexit.x64"),
        ]
        vmmap = p.memory.vmmap
        for i in range(len(known_mem)):
            self.assertEqual(vmmap[i].start, known_mem[i][0])
            self.assertEqual(vmmap[i].end, known_mem[i][1])
            self.assertEqual(vmmap[i].offset, known_mem[i][2])
            self.assertEqual(vmmap[i].perm, known_mem[i][3])
            self.assertTrue(vmmap[i].path.endswith(known_mem[i][4]))

        stack_found = vvar_found = vdso_found = vsyscall_found = False
        for mem in vmmap:
            if mem.path == '[stack]' and mem.perm == 'rw-p':
                stack_found = True
            elif mem.path == '[vvar]' and mem.perm == 'r--p':
                vvar_found = True
            elif mem.path == '[vdso]' and mem.perm == 'r-xp':
                vdso_found = True
            elif mem.path == '[vsyscall]' and mem.perm == '--xp':
                vsyscall_found = True

        self.assertTrue(stack_found)
        self.assertTrue(vvar_found)
        self.assertTrue(vdso_found)
        self.assertTrue(vsyscall_found)

        p.close()

    def test_read(self):
        p = Process("./tests/test.bin/fastexit.x64")

        self.assertEqual(p.memory.read(0x400000, 4), b'\x7fELF')
        self.assertEqual(p.memory.read(0x40b008, 5), b'Hello')

        with self.assertRaises(OSError):
            p.memory.read(0xdead0000, 4)

        data = p.memory.read(0x400000, 0x2000)
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "1c2d10505b9ca8ac7e791c9f5c0d219c438f17178e0636e731eba2e4a34049be")

        environ = struct.unpack('<Q', p.memory.read(0x40eb28, 8))[0]
        argv0 = struct.unpack('<Q', p.memory.read(environ - 0x10, 8))[0]
        self.assertEqual(p.memory.read(argv0, 30), b'./tests/test.bin/fastexit.x64\0')

        p.sendline("10")
        for i in range(10):
            self.assertEqual(p.recvline(), f'[{i}] Hello, World!'.encode())
        self.assertEqual(p.recvline(), b'END')

        p.close()

    def test_write(self):
        p = Process("./tests/test.bin/fastexit.x64")

        with self.assertRaises(OSError):
            p.memory.write(0xdead0000, b"DEAD")

        p.memory.write(0x400000, b"A"*0x1000)
        p.memory.write(0x40b008, b'ABCDE')
        p.memory.write(0x400000, "A"*0x1000)
        p.memory.write(0x40b008, 'ABCDE')

        p.sendline("10")
        for i in range(10):
            self.assertEqual(p.recvline(), f'[{i}] ABCDE, World!'.encode())
        self.assertEqual(p.recvline(), b'END')

        p.close()

    def test_search(self):
        p = Process("./tests/test.bin/fastexit.x64")

        g = p.memory.search("Hello")
        self.assertEqual(next(g), 0x40b008)
        with self.assertRaises(StopIteration):
            next(g)

        g = p.memory.search(b"\0\0\0\0\0\0\0\0\x50\x58\xc3\0\0\0\0\0")
        self.assertEqual(next(g), 0x400ff8)
        with self.assertRaises(StopIteration):
            next(g)

        environ = struct.unpack('<Q', p.memory.read(0x40eb28, 8))[0]
        argv0 = struct.unpack('<Q', p.memory.read(environ - 0x10, 8))[0]
        self.assertEqual(next(p.memory.search(b'./tests/test.bin/fastexit.x64')), argv0)

        with self.assertRaises(StopIteration):
            next(p.memory.search(b"\x00\x25", start=0x40aff0, length=0xf))
        self.assertEqual(next(p.memory.search(b"\x00\x25", start=0x40aff0, length=0x10)), 0x40afff)

        p.close()
