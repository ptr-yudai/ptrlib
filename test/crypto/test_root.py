import unittest
import random
from ptrlib import root, rootrem
from logging import getLogger, FATAL


class TestRoot(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_rootrem(self):
        for _ in range(10):
            x = random.randint(0, 1<<512)
            n = random.randint(2, 32)
            r = random.randrange(0, abs(x))
            y = x ** n + r

            xx, rr = rootrem(y, n)

            self.assertEqual(xx, x)
            self.assertEqual(rr, r)

    def test_root(self):
        for _ in range(10):
            x = random.randint(0, 1<<512)
            n = random.randint(2, 32)
            r = random.randrange(0, abs(x))
            y = x ** n + r

            xx = root(y, n)

            self.assertEqual(xx, x)
