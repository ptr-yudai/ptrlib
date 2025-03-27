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

    def test_flat(self):
        """Tests for flat.
        """
        l = [1, 2, 3, 4]
        self.assertEqual(flat(l, map=p8), b'\x01\x02\x03\x04')
        self.assertEqual(flat(l, map=p32), p32(1)+p32(2)+p32(3)+p32(4))
        self.assertEqual(flat(l, map=p64), p64(1)+p64(2)+p64(3)+p64(4))
