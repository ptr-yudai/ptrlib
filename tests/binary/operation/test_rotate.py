import unittest
from ptrlib import ror, rol
from logging import getLogger, FATAL


class TestRotate(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_ror(self):
        self.assertEqual(ror([1,2,3,4,5], 3), [3,4,5,1,2])
        self.assertEqual(ror([1,2,3,4,5,6,7], 1), [7,1,2,3,4,5,6])
        self.assertEqual(ror(b"abcd", 1), b"dabc")
        self.assertEqual(ror(b"abcd", 4), b"abcd")
        self.assertEqual(ror(0xde, 4, bits=8), 0xed)
        self.assertEqual(ror(0b1110001, 3, bits=7), 0b0011110)
        self.assertEqual(ror(0xdeadbeef, 16, bits=32), 0xbeefdead)
        self.assertEqual(ror(0x1122334455667788, 48, bits=64),
                         0x3344556677881122)

    def test_rol(self):
        self.assertEqual(rol([1,2,3,4,5], 3), [4,5,1,2,3])
        self.assertEqual(rol([1,2,3,4,5,6,7], 1), [2,3,4,5,6,7,1])
        self.assertEqual(rol(b"abcd", 1), b"bcda")
        self.assertEqual(rol(b"abcd", 4), b"abcd")
        self.assertEqual(rol(0xde, 4, bits=8), 0xed)
        self.assertEqual(rol(0b1110001, 3, bits=7), 0b0001111)
        self.assertEqual(rol(0xdeadbeef, 16, bits=32), 0xbeefdead)
        self.assertEqual(rol(0x1122334455667788, 48, bits=64),
                         0x7788112233445566)
