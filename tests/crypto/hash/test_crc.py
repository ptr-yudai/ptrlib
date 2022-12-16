import unittest
import os
from ptrlib import crc32, rev_crc32
import binascii
from hashlib import md5, sha1, sha256
from logging import getLogger, FATAL


class TestCRC(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_crc32(self):
        self.assertEqual(binascii.crc32(b'a'), crc32(b'a'))

        m = os.urandom(32)
        self.assertEqual(binascii.crc32(m), crc32(m))

    def test_rev_crc32(self):
        m = os.urandom(32)
        target = 0xCAFEBABE
        r = rev_crc32(m, target)
        self.assertEqual(crc32(m + r), target)
