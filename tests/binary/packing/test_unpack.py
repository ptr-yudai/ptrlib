import unittest
from ptrlib import u8, u16, u32, u64, u32f, u64f
from logging import getLogger, FATAL


class TestUnpack(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_p8(self):
        v = '\xff'
        self.assertEqual(u8(v), 0xff)
        self.assertEqual(u8(v, signed=True), -1)

    def test_u16(self):
        v = b'\xcc\xed'
        self.assertEqual(u16(v), 0xedcc)
        self.assertEqual(u16(v, signed=True), -0x1234)
        v = b'\xed\xcc'
        self.assertEqual(u16(v, byteorder='big'), 0xedcc)
        self.assertEqual(u16(v, byteorder='big', signed=True), -0x1234)

    def test_u32(self):
        v = b'\x88\xa9\xcb\xed'
        self.assertEqual(u32(v), 0xedcba988)
        self.assertEqual(u32(v, signed=True), -0x12345678)
        v = b'\xed\xcb\xa9\x88'
        self.assertEqual(u32(v, byteorder='big'), 0xedcba988)
        self.assertEqual(u32(v, byteorder='big', signed=True), -0x12345678)
        v = b'\x00\x00\x40\x40'
        self.assertEqual(u32f(v), 3.0)
        self.assertEqual(u32f(v[::-1], byteorder='big'), 3.0)

    def test_u64(self):
        v = b'\x11\x32\x54\x6f\x87\xa9\xcb\xed'
        self.assertEqual(u64(v), 0xedcba9876f543211)
        self.assertEqual(u64(v, signed=True), -0x1234567890abcdef)
        v = b'\xed\xcb\xa9\x87\x6f\x54\x32\x11'
        self.assertEqual(u64(v, byteorder='big'), 0xedcba9876f543211)
        self.assertEqual(u64(v, byteorder='big', signed=True),
                         -0x1234567890abcdef)
        v = b'\xf1\xd4\xc8\x53\xfb\x21\x09\x40'
        self.assertEqual(u64f(v), 3.14159265)
        self.assertEqual(u64f(v[::-1], byteorder='big'), 3.14159265)
