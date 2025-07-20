"""This package provides some tests for the chunks function.
"""
import random
import unittest
from logging import getLogger, FATAL
from ptrlib import chunks, u16, u32


class TestChunks(unittest.TestCase):
    """Tests for chunks.
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_chunks_str(self):
        """Tests for string chunks.
        """
        self.assertEqual(chunks('', random.randint(1, 9999)),
                         [])
        self.assertEqual(chunks('AAA', random.randint(3, 9999)),
                         ["AAA"])
        self.assertEqual(chunks('AAAABBBBCC', 4),
                         ["AAAA", "BBBB", "CC"])
        self.assertEqual(chunks('AAAABBBBCC', 4, padding='\x00'),
                         ["AAAA", "BBBB", "CC\x00\x00"])

    def test_chunks_bytes(self):
        """Tests for bytes chunks.
        """
        self.assertEqual(chunks(b'', random.randint(1, 9999)),
                         [])
        self.assertEqual(chunks(b'AAA', random.randint(3, 9999)),
                         [b"AAA"])
        self.assertEqual(chunks(b'AAAABBBBCC', 4),
                         [b"AAAA", b"BBBB", b"CC"])
        self.assertEqual(chunks(b'AAAABBBBCC', 4, padding=b'\x00'),
                         [b"AAAA", b"BBBB", b"CC\x00\x00"])
        self.assertEqual(chunks(bytearray(b'AAAABBBBCC'), 4, padding=bytearray(b'\x00')),
                         [bytearray(b"AAAA"),
                          bytearray(b"BBBB"),
                          bytearray(b"CC\x00\x00")])

    def test_chunks_list(self):
        """Tests for list chunks.
        """
        self.assertEqual(chunks([], random.randint(1, 9999)),
                         [])
        self.assertEqual(chunks([1.1, 2.2, 3.3, 4.4, 5.5, 6.6], 4),
                         [[1.1, 2.2, 3.3, 4.4], [5.5, 6.6]])
        self.assertEqual(chunks([1,2,3,4,4,3,2], 4, padding=[-1]),
                         [[1,2,3,4], [4,3,2,-1]])
        self.assertEqual(chunks(["a", b"b", 0x43], 2, padding=[{"hello": "world"}]),
                         [["a", b"b"], [0x43, {"hello": "world"}]])
