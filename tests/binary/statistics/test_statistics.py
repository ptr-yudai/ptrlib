import unittest
from ptrlib import consists_of
from logging import getLogger, FATAL


class TestStatistics(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_consists_of(self):
        self.assertEqual(consists_of("AAAABBBBAAAA", "A", returns=float), 8/12)
        self.assertEqual(consists_of(b"BAAABABA", b"A", returns=float), 5/8)
        self.assertEqual(consists_of([1,2,3,4], [1,2], returns=float), 2/4)
        self.assertEqual(consists_of([1,2,2,1], [1,2], per=1.0), True)
        self.assertEqual(consists_of([1,2,3,1], [1,2], per=1.0), False)
        self.assertEqual(consists_of([1,2,2,1,2,2,1], [1,2], per=0.8), True)
        self.assertEqual(consists_of([1,2,2,1,3,2,1], [1,2], per=0.8), True)
        self.assertEqual(consists_of([1,2,3,1,3,2,1], [1,2], per=0.8), False)
        self.assertEqual(consists_of("314159265", "0123456789", per=0.8), True)
        self.assertEqual(consists_of("3?4159265", "0123456789", per=0.8), True)
        self.assertEqual(consists_of("3?41?9265", "0123456789", per=0.8), False)
