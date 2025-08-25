import inspect
import os
import random
import subprocess
import unittest
from logging import FATAL, getLogger

from ptrlib import Process, is_token, TubeTimeout

_is_windows = os.name == 'nt'


class TestWinProcess(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if not _is_windows:
            self.skipTest("This test is for Windows architecture")

    def test_basic(self):
        """Basic tests
        """
        p = Process("./tests/test.bin/test_echo.pe.exe")
        p.sendline(["\x01\x10\x80\xff", b"\xde\x02\xad\x20\xbe\x90\xef\xee"])
        self.assertEqual(p.recvline(), b"\x01\x10\x80\xff")
        self.assertEqual(p.recvline(), b"\xde\x02\xad\x20\xbe\x90\xef\xee")

        candidates = ["Cat", "Dog", "Bird", "Fish", "Hamster"]
        answer = random.choice(candidates)
        p.sendline(answer)
        self.assertEqual(p.recvuntil(answer), answer.encode())

        p.sendline(b"Message: This is a 'test message'")
        r = p.after(": ").recvregex(r"'(.+)'")
        self.assertEqual(r.group(1), b"test message")

        candidates = ["Cat", "Dog", "Bird", "Fish", "Hamster"]
        answer = random.choice(candidates)
        p.sendline(answer + " is cute!")
        line = p.after(regex=[r".{3}\s", r".{4}\s", r"Hamster\s"]).recvline()
        self.assertEqual(line, b"is cute!")

        p.close()

    def test_compatibility(self):
        """Old basic tests
        """
        module_name = inspect.getmodule(Process).__name__

        while True:
            msg = os.urandom(16)
            if is_token(msg, False) and b'\x1a' not in msg:
                break

        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_echo.pe.exe")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                         f'INFO:{module_name}:Successfully created a new process {str(p)}')
        pid = p.pid

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
        self.assertEqual(int(r.group(1), 16), a)
        self.assertEqual(int(r[2], 16), b)

        # sendlineafter
        a, b = os.urandom(16).hex(), os.urandom(16).hex()
        p.sendline(a)
        v = p.sendlineafter(a + "\r\n", b)
        self.assertEqual(v, len(b) + len(p.newline))
        self.assertEqual(p.recvline().strip(), b.encode())

        # shutdown
        p.send(msg[::-1])
        p.close_send()
        self.assertEqual(p.recvall(len(msg)), msg[::-1])

        # wait
        with self.assertLogs(module_name) as cm:
            self.assertEqual(p.wait(), 0)
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                         f'INFO:{module_name}:Process {str(p)} stopped with exit code 0')

        self.assertEqual(p.wait(), 0)
        p.close()
        self.assertFalse(str(pid) in subprocess.getoutput(f'tasklist /FI "PID eq {pid}"').split())

    def test_timeout(self):
        """Timeout tests
        """
        mod = inspect.getmodule(Process)
        assert mod is not None
        module_name = mod.__name__

        with self.assertLogs(module_name) as cm:
            p = Process("./tests/test.bin/test_echo.pe.exe")
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(cm.output[0],
                         f'INFO:{module_name}:Successfully created a new process {str(p)}')
        data = os.urandom(16).hex()

        # recv
        with self.assertRaises(TubeTimeout) as cm:
            p.recv(timeout=0.5)
        self.assertEqual(cm.exception.buffered, b"")

        # recvonce
        p.sendline(data)
        with self.assertRaises(TubeTimeout) as cm:
            p.recvall(len(data) + len(p.newline) + 1, timeout=0.5)
        self.assertEqual(cm.exception.buffered.decode().strip(), data)

        # recvuntil
        p.sendline(data)
        with self.assertRaises(TubeTimeout) as cm:
            p.recvuntil("*** never expected ***", timeout=0.5)
        self.assertEqual(cm.exception.buffered.decode().strip(), data)

        # sendlineafter
        a, b = os.urandom(16).hex(), os.urandom(16).hex()
        p.sendline(a)
        with self.assertRaises(TubeTimeout) as cm:
            p.sendlineafter(b"neko", b, timeout=0.5)
        self.assertEqual(cm.exception.buffered.decode().strip(), a)
