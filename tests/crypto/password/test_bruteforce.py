import unittest
from ptrlib import bruteforce, table_digits
from logging import getLogger, FATAL


class TestBruteforce(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_bruteforce(self):
        it = bruteforce(4)
        self.assertEqual(next(it), b'\x00\x00\x00\x00')
        self.assertEqual(next(it), b'\x00\x00\x00\x01')
        self.assertEqual(next(it), b'\x00\x00\x00\x02')
        self.assertEqual(next(it), b'\x00\x00\x00\x03')

        it = bruteforce(2, charset='ABC')
        self.assertEqual(next(it), 'AA')
        self.assertEqual(next(it), 'AB')
        self.assertEqual(next(it), 'AC')
        self.assertEqual(next(it), 'BA')
        self.assertEqual(next(it), 'BB')

        it = bruteforce(3, charset=['xx', 'yy'])
        self.assertEqual(next(it), 'xxxxxx')
        self.assertEqual(next(it), 'xxxxyy')
        self.assertEqual(next(it), 'xxyyxx')

        it = bruteforce(3, charset=[b'xx', b'yy'])
        self.assertEqual(next(it), b'xxxxxx')
        self.assertEqual(next(it), b'xxxxyy')
        self.assertEqual(next(it), b'xxyyxx')

        it = bruteforce(1, 4, table_digits)
        self.assertEqual(next(it), '0')
        for i in range(9): next(it)
        self.assertEqual(next(it), '00')
        for i in range(99): next(it)
        self.assertEqual(next(it), '000')
        for i in range(999): next(it)
        self.assertEqual(next(it), '0000')
        for i in range(1234-1): next(it)
        self.assertEqual(next(it), '1234')
