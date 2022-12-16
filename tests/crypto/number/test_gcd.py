import math
import random
import unittest
from ptrlib import gcd, xgcd
from logging import getLogger, FATAL


class TestGCD(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_gcd(self):
        for _ in range(30):
            x = y = 0
            while x == 0 or y == 0:
                x = random.randint(-1<<512, 1<<512)
                y = random.randint(-1<<512, 1<<512)

            z = gcd(x, y)

            self.assertEqual(z, math.gcd(x, y))

    def test_xgcd(self):
        for _ in range(30):
            x = random.randint(1, 1<<512)
            y = random.randint(1, 1<<512)

            c, a, b = xgcd(x, y)

            self.assertEqual(a * x + b * y, c)
            self.assertEqual(c, math.gcd(x, y))
