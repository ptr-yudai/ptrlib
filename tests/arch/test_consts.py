import unittest
from ptrlib import consts
from logging import getLogger, FATAL


class TestConsts(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_consts(self):
        self.assertEqual(consts['x86']['EFAULT'], 14)
        self.assertEqual(consts['i386']['EPERM'], 1)
        self.assertEqual(consts['O_RDWR'], 2)
        self.assertEqual(consts['ELF_NOTE_SOLARIS'], "SUNW Solaris")

        self.assertEqual(consts.i386.READ_IMPLIES_EXEC, 0x400000)
        self.assertEqual(consts.x64.AT_RECURSIVE, 0x8000)
        self.assertEqual(consts.amd64.ENOENT, 2)
        self.assertEqual(consts.MAP_PRIVATE | consts.MAP_ANONYMOUS, 0x22)

        with self.assertRaises(KeyError):
            _ = consts.PTRLIB
        with self.assertRaises(KeyError):
            _ = consts.x64.PTRLIB
