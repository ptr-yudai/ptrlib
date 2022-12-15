import unittest
import os
from logging import getLogger, FATAL
from ptrlib.crypto.blockcipher import pad, unpad


class TestPadding(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_pad(self):
        # Zero padding
        dat = pad(b'Hello', 8, 'zero')
        self.assertEqual(dat, b'Hello\0\0\0')
        dat = pad(b'Hello!!!', 8, 'zero')
        self.assertEqual(dat, b'Hello!!!' + b'\0'*8)
        dat = pad('Hello, World!', 8, 'zero')
        self.assertEqual(dat, b'Hello, World!\0\0\0')
        dat = pad(b'abc', 5, 'zero')
        self.assertEqual(dat, b'abc\0\0')

        # PKCS#5 padding
        dat = pad(b'Hello', 8)
        self.assertEqual(dat, b'Hello\x03\x03\x03')
        dat = pad(b'Hello!!!', 8)
        self.assertEqual(dat, b'Hello!!!' + b'\x08'*8)
        dat = pad('Hello, World!', 8)
        self.assertEqual(dat, b'Hello, World!\x03\x03\x03')
        dat = pad(b'abc', 5)
        self.assertEqual(dat, b'abc\x02\x02')
        

    def test_unpad(self):
        # Zero padding
        dat = pad(b'Hello', 8, 'zero')
        self.assertEqual(unpad(dat, 'zero'), b'Hello')
        dat = pad(b'Hello!!!', 8, 'zero')
        self.assertEqual(unpad(dat, 'zero'), b'Hello!!!')
        dat = pad('Hello, World!', 8, 'zero')
        self.assertEqual(unpad(dat, 'zero'), b'Hello, World!')
        dat = pad(b'abc', 5, 'zero')
        self.assertEqual(unpad(dat, 'zero'), b'abc')

        # PKCS#5 padding
        dat = pad(b'Hello', 8)
        self.assertEqual(unpad(dat), b'Hello')
        dat = pad(b'Hello!!!', 8)
        self.assertEqual(unpad(dat), b'Hello!!!')
        dat = pad('Hello, World!', 8)
        self.assertEqual(unpad(dat), b'Hello, World!')
        dat = pad(b'abc', 5)
        self.assertEqual(unpad(dat), b'abc')
        
