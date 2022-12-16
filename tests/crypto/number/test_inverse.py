import random
import unittest
from ptrlib import inverse
from logging import getLogger, FATAL
from Crypto.Util.number import getPrime


class TestInverse(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_inverse(self):
        for n in [64, 128, 256, 512]:
            p = getPrime(n)
            for _ in range(30):
                a = random.randrange(1, p)
                ai = inverse(a, p)

                self.assertEqual((a * ai) % p, 1)
