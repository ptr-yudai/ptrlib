import os
import unittest
from ptrlib.arch.intel.cpu import *
from logging import getLogger, FATAL


class TestCPU(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_crc32(self):
        self.assertEqual(intel_crc32(0, b'\0'*1), 0)
        self.assertEqual(intel_crc32(0, b'\0'*2), 0)
        self.assertEqual(intel_crc32(0, b'\0'*4), 0)
        self.assertEqual(intel_crc32(0, b'\0'*8), 0)
        self.assertEqual(intel_crc32(0xdeadbeef, b'!'), 0x6f2b345d)
        self.assertEqual(intel_crc32(0xdeadbeef, b'NO'), 0x96efb357)
        self.assertEqual(intel_crc32(0xdeadbeef, b'nyan'), 0xd2081c24)
        self.assertEqual(intel_crc32(0xdeadbeef, b'gorilla.'), 0x51a0e90)
        self.assertEqual(intel_crc32(0x11223344, b'\0'*1), 0x86f0a890)
        self.assertEqual(intel_crc32(0x11223344, b'\0'*2), 0x922e0cbf)
        self.assertEqual(intel_crc32(0x11223344, b'\0'*4), 0x11b7bf79)
        self.assertEqual(intel_crc32(0x11223344, b'\0'*8), 0xcb53fd2d)
        self.assertEqual(intel_crc32(0, b'a'), 0x93ad1061)
        self.assertEqual(intel_crc32(0, b'ab'), 0x13c35ee4)
        self.assertEqual(intel_crc32(0, b'abcd'), 0xdaaf41f6)
        self.assertEqual(intel_crc32(0, b'abcdefgh'), 0x86bc933d)
