import unittest
from ptrlib import p8, p16, p32, p64
from logging import getLogger, FATAL


class TestPack(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_p8(self):
        v = 0x1
        self.assertEqual(p8(v), b'\x01')
        self.assertEqual(p8(-v), b'\xff')

    def test_p16(self):
        v = 0x1234
        self.assertEqual(p16(v), b'\x34\x12')
        self.assertEqual(p16(-v), b'\xcc\xed')
        self.assertEqual(p16(v, byteorder='big'), b'\x12\x34')
        self.assertEqual(p16(-v, byteorder='big'), b'\xed\xcc')

    def test_p32(self):
        v = 0x12345678
        self.assertEqual(p32(v), b'\x78\x56\x34\x12')
        self.assertEqual(p32(-v), b'\x88\xa9\xcb\xed')
        self.assertEqual(p32(v, byteorder='big'), b'\x12\x34\x56\x78')
        self.assertEqual(p32(-v, byteorder='big'), b'\xed\xcb\xa9\x88')
        v = 3.14
        self.assertEqual(p32(v), b'\xc3\xf5\x48\x40')
        self.assertEqual(p32(v, byteorder='big'), b'\x40\x48\xf5\xc3')

    def test_p64(self):
        v = 0x1234567890abcdef
        self.assertEqual(p64(v), b'\xef\xcd\xab\x90\x78\x56\x34\x12')
        self.assertEqual(p64(-v), b'\x11\x32\x54\x6f\x87\xa9\xcb\xed')
        self.assertEqual(p64(v, byteorder='big'),
                         b'\x12\x34\x56\x78\x90\xab\xcd\xef')
        self.assertEqual(p64(-v, byteorder='big'),
                         b'\xed\xcb\xa9\x87\x6f\x54\x32\x11')
        v = 3.14159265
        self.assertEqual(p64(v), b'\xf1\xd4\xc8\x53\xfb\x21\x09\x40')
        self.assertEqual(p64(v, byteorder='big'),
                         b'\x40\x09\x21\xfb\x53\xc8\xd4\xf1')
