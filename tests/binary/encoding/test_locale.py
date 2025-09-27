import sys
import unittest
from logging import getLogger, FATAL
from io import StringIO
from ptrlib.binary.encoding.char import is_line, is_token, assert_line, assert_token


class TestLocale(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_is_token(self):
        """Test for `is_token` and `assert_token`
        """
        self.assertFalse(is_token(b'AABB\x20CCDD', False))
        self.assertFalse(is_token(b'AABB\x09CCDD', False))
        self.assertFalse(is_token(b'AABB\x0aCCDD', False))
        self.assertFalse(is_token('AABB\x0bCCDD', False))
        self.assertFalse(is_token('AABB\x0cCCDD', False))
        self.assertFalse(is_token('AABB\x0dCCDD', False))
        self.assertTrue(is_token(b'AABB\xffCCDD', False))
        self.assertTrue(is_token(b'AABB\xa0CCDD', False))
        self.assertTrue(is_token(b'AABB\x21CCDD', False))
        self.assertTrue(is_token('AABB\x80CCDD', False))
        self.assertTrue(is_token('AABB\x7fCCDD', False))
        self.assertTrue(is_token('AABB\x1fCCDD', False))

        with self.assertRaises(ValueError):
            assert_token(b'AABB\x20CCDD', False)
        with self.assertRaises(ValueError):
            assert_token(b'AABB\x0aCCDD', False)
        with self.assertRaises(ValueError):
            assert_token(b'AABB\x0cCCDD', False)
        self.assertEqual(assert_token(b'AAAABBBB'), b'AAAABBBB')
        self.assertEqual(assert_token('nekomaruke'), 'nekomaruke')

    def test_is_line(self):
        """Test for `is_line` and `assert_line`
        """
        self.assertTrue(is_line(b'AABB\x09CCDD', False))
        self.assertFalse(is_line(b'AABB\x0aCCDD', False))
        self.assertTrue(is_line(b'AABB\x0bCCDD', False))
        self.assertTrue(is_line('AABB\x80CCDD', False))
        self.assertFalse(is_line('AABB\x0aCCDD', False))
        self.assertTrue(is_line('AABB\x1fCCDD', False))

        with self.assertRaises(ValueError):
            assert_line(b"AABB\x0aCCDD", False)
        with self.assertRaises(ValueError):
            assert_line("AABB\x0aCCDD", False)
        self.assertEqual(assert_line(b'AAAABBBB'), b'AAAABBBB')
        self.assertEqual(assert_line('nekomaruke'), 'nekomaruke')
