"""This package provides some tests for the chunks function.
"""
import unittest
from logging import getLogger, FATAL
from ptrlib import chunks, u16, u32


class TestChunks(unittest.TestCase):
    """Tests for chunks.
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_chunks(self):
        """Tests for chunks.
        """
        self.assertEqual(chunks(b'AAA', 3), [b"AAA"])
        self.assertEqual(chunks(b'AAAABBBBCC', 4),
                         [b"AAAA", b"BBBB", b"CC"])
        self.assertEqual(chunks(b'AAAABBBBCC', 4, padding=b'\x00'),
                         [b"AAAA", b"BBBB", b"CC\x00\x00"])
        self.assertEqual(chunks(b'\x01\x00\x02\x00\x03\x00', 2, map=u16),
                         [1, 2, 3])
        self.assertEqual(chunks(b'\x01\x00\x02\x00\x03\x00', 4, map=u32),
                         [0x20001, 3])
        self.assertEqual(chunks([1,2,3,4, 4,3,2], 4, padding=[-1]),
                         [[1,2,3,4], [4,3,2,-1]])
