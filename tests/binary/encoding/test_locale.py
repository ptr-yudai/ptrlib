import unittest
from ptrlib.binary.encoding.locale import *
from logging import getLogger, FATAL


class TestLocale(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_has_space(self):
        self.assertEqual(has_space(b'AABB\x20CCDD', False), True)
        self.assertEqual(has_space(b'AABB\x09CCDD', False), True)
        self.assertEqual(has_space(b'AABB\x0aCCDD', False), True)
        self.assertEqual(has_space(b'AABB\x0bCCDD', False), True)
        self.assertEqual(has_space(b'AABB\x0cCCDD', False), True)
        self.assertEqual(has_space(b'AABB\x0dCCDD', False), True)
        self.assertEqual(has_space(b'AABB\xffCCDD', False), False)
        self.assertEqual(has_space(b'AABB\xa0CCDD', False), False)
        self.assertEqual(has_space(b'AABB\x21CCDD', False), False)
        self.assertEqual(has_space(b'AABB\x80CCDD', False), False)
        self.assertEqual(has_space(b'AABB\x7fCCDD', False), False)
        self.assertEqual(has_space(b'AABB\x1fCCDD', False), False)

    def test_is_scanf_safe(self):
        self.assertEqual(is_scanf_safe(b'AABB\x20CCDD', False), False)
        self.assertEqual(is_scanf_safe(b'AABB\x09CCDD', False), False)
        self.assertEqual(is_scanf_safe(b'AABB\x0aCCDD', False), False)
        self.assertEqual(is_scanf_safe(b'AABB\x0bCCDD', False), False)
        self.assertEqual(is_scanf_safe(b'AABB\x0cCCDD', False), False)
        self.assertEqual(is_scanf_safe(b'AABB\x0dCCDD', False), False)
        self.assertEqual(is_scanf_safe(b'AABB\xffCCDD', False), True)
        self.assertEqual(is_scanf_safe(b'AABB\xa0CCDD', False), True)
        self.assertEqual(is_scanf_safe(b'AABB\x21CCDD', False), True)
        self.assertEqual(is_scanf_safe(b'AABB\x80CCDD', False), True)
        self.assertEqual(is_scanf_safe(b'AABB\x7fCCDD', False), True)
        self.assertEqual(is_scanf_safe(b'AABB\x1fCCDD', False), True)

    def test_is_fgets_safe(self):
        self.assertEqual(is_fgets_safe(b'AABB\x20CCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\x09CCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\x0aCCDD', False), False)
        self.assertEqual(is_fgets_safe(b'AABB\x0bCCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\x0cCCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\x0dCCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\xffCCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\xa0CCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\x21CCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\x80CCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\x7fCCDD', False), True)
        self.assertEqual(is_fgets_safe(b'AABB\x1fCCDD', False), True)
