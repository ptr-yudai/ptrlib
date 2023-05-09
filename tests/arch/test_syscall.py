import unittest
from ptrlib import syscall
from logging import getLogger, FATAL


class TestSyscall(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_syscall(self):
        self.assertEqual(syscall['x86']['read'], 3)
        self.assertEqual(syscall['i386']['read'], 3)
        self.assertEqual(syscall['x86-64']['read'], 0)
        self.assertEqual(syscall['amd64']['read'], 0)
        self.assertEqual(syscall['arm']['read'], 3)
        self.assertEqual(syscall['aarch32']['read'], 3)
        self.assertEqual(syscall['arm64']['read'], 63)
        self.assertEqual(syscall['aarch64']['read'], 63)

        self.assertEqual(syscall.i386.open, 5)
        self.assertEqual(syscall.x86.execve, 11)
        self.assertEqual(syscall.x64.execve, 59)
        self.assertEqual(syscall.x86_64.futex, 202)
        self.assertEqual(syscall.arm.futex_time32, 240)
        self.assertEqual(syscall.arm.futex, 422)
        self.assertEqual(syscall.arm32.open_by_handle_at, 371)
        self.assertEqual(syscall.aarch64.accept, 202)
        self.assertEqual(syscall.arm64.vhangup, 58)
