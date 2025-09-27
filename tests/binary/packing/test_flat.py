"""This package provides some tests for the flat function.
"""
import unittest
from logging import getLogger, FATAL
from ptrlib import flat, p8, p32, p64


class TestFlat(unittest.TestCase):
    """Tests for flat.
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_flat_int(self):
        """Tests for int flat.
        """
        l = [1, 2, 3, 4]
        self.assertEqual(flat(l, map=p8), b'\x01\x02\x03\x04')
        self.assertEqual(flat(l, map=p32), p32(1)+p32(2)+p32(3)+p32(4))
        self.assertEqual(flat(l, map=p64), p64(1)+p64(2)+p64(3)+p64(4))

    def test_flat_float(self):
        """Tests for float flat.
        """
        l = [3.14, 2.17, 1.1]
        self.assertEqual(
            flat(l, map=p32),
            b'\xc3\xf5H@H\xe1\n@\xcd\xcc\x8c?'
        )
        self.assertEqual(
            flat(l, map=p64),
            b'\x1f\x85\xebQ\xb8\x1e\t@\\\x8f\xc2\xf5(\\\x01@\x9a\x99\x99\x99\x99\x99\xf1?'
        )
