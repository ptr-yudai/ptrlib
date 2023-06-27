import unittest
from ptrlib import str2bytes, bytes2str, bytes2utf8
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

    def test_bytes2utf8(self):
        b1 = b'\xe3\x81\xab\xe3\x82\x83\xe3\x83\xbc\xe3\x82\x93\xf0\x9f\x98\xba\xf0\x9f\x90\xb6\xe3\x82\x8f\xe3\x82\x93\xe3\x82\x8f\xe3\x82\x93\xe3\x81\x8a'
        b2 = b'\xd0\xba\xd0\xbe\xd1\x82\xea\xb3\xa0\xec\x96\x91\xec\x9d\xb4\xd9\x82\xd8\xb7\xd8\xa9'
        b3 = b'\xf0\x9f\x98\xbaNEKO\xe3NEKO'

        s, leftover, marker = bytes2utf8(b1)
        self.assertEqual(s.encode('utf-8'), b1)
        self.assertEqual(len(leftover), 0)
        self.assertEqual(all(marker), True)

        s, leftover, marker = bytes2utf8(b2)
        self.assertEqual(s.encode('utf-8'), b2)
        self.assertEqual(len(leftover), 0)
        self.assertEqual(all(marker), True)

        s, leftover, marker = bytes2utf8(b1[:len(b1)//2])
        self.assertEqual(s.encode('utf-8'), b1[:3+3+3+3+4])
        self.assertEqual(leftover, b1[3+3+3+3+4:len(b1)//2])
        self.assertEqual(all(marker), True)

        s, leftover, marker = bytes2utf8(b1[len(b1)//2:])
        self.assertEqual(s[:3], '\x9f\x90\xb6')
        self.assertEqual(len(leftover), 0)
        self.assertEqual(all(marker), True)

        s, leftover, marker = bytes2utf8(b3)
        self.assertEqual(len(leftover), 0)
        self.assertEqual(all(marker[:5]), True)
        self.assertEqual(marker[5], False)
        self.assertEqual(all(marker[6:]), True)
