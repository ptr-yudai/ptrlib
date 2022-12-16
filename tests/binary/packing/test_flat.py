import unittest
from ptrlib import flat, p8, p32, p64
from logging import getLogger, FATAL


class TestFlat(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_flat(self):
        inc = lambda x: [x + 1]
        l = [1, 2, 3, 4]
        self.assertEqual(flat(l), 1+2+3+4)
        self.assertEqual(flat(l, map=inc), [2,3,4,5])
        self.assertEqual(flat(l, map=p8), b'\x01\x02\x03\x04')
        self.assertEqual(flat(l, map=p32), p32(1)+p32(2)+p32(3)+p32(4))
        self.assertEqual(flat(l, map=p64), p64(1)+p64(2)+p64(3)+p64(4))
