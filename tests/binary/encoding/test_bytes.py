import unittest
from ptrlib import str2bytes, bytes2str
from logging import getLogger, FATAL


class TestBytes(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_str2bytes(self):
        self.assertEqual(str2bytes("Hello"), b"Hello")
        self.assertEqual(str2bytes("\x01\x80\n\xfe\x7f\x00"),
                         b"\x01\x80\n\xfe\x7f\x00")

    def test_bytes2str(self):
        self.assertEqual(bytes2str(b"Hello"), "Hello")
        self.assertEqual(bytes2str(b"\x01\x80\n\xfe\x7f\x00"),
                         "\x01\x80\n\xfe\x7f\x00")
