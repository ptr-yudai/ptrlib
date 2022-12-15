import unittest
from ptrlib import xor
from logging import getLogger, FATAL


class TestXor(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_xor(self):
        self.assertEqual(xor(b"AAAA", b"\x01\x02"), b"@C@C")
        self.assertEqual(xor(b"AAAA", b"\x01\x02\x03\x04\x05\x06"), b"@CBE")
        self.assertEqual(xor("AAAABBBB", "\x01"), b"@@@@CCCC")
        self.assertEqual(xor("AAAA", [1,2]), b"@C@C")
        self.assertEqual(xor([0x41, 0x41, 0x41, 0x42], [1,2,3]), b"@CBC")
        self.assertEqual(xor("AAAA", 1), b"@@@@")
        self.assertEqual(xor([0xf0, 0x70, 0x80], 0x10), b'\xe0\x60\x90')
