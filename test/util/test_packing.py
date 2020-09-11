import unittest
from ptrlib import p16, p32, p64, u16, u32, u64
from logging import getLogger, FATAL

class TestFSB(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

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
        self.assertEqual(u32(v, type=float), 3.0)
        self.assertEqual(u32(v[::-1], byteorder='big', type=float), 3.0)

    def test_u64(self):
        v = b'\x11\x32\x54\x6f\x87\xa9\xcb\xed'
        self.assertEqual(u64(v), 0xedcba9876f543211)
        self.assertEqual(u64(v, signed=True), -0x1234567890abcdef)
        v = b'\xed\xcb\xa9\x87\x6f\x54\x32\x11'
        self.assertEqual(u64(v, byteorder='big'), 0xedcba9876f543211)
        self.assertEqual(u64(v, byteorder='big', signed=True),
                         -0x1234567890abcdef)
        v = b'\xf1\xd4\xc8\x53\xfb\x21\x09\x40'
        self.assertEqual(u64(v, type=float), 3.14159265)
        self.assertEqual(u64(v[::-1], byteorder='big', type=float),
                         3.14159265)

if __name__ == '__main__':
    unittest.main()
