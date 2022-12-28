import random
import unittest
from ptrlib import crt
from logging import getLogger, FATAL
from Crypto.Util.number import getPrime


class TestCRT(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_crt(self):
        for n in [64, 128, 256]:
            for _ in range(30):
                xlist = []
                plist = []
                for i in range(random.randint(2, 10)):
                    p = getPrime(n)
                    plist.append(p)
                    xlist.append(random.randrange(0, p))

                y = crt(xlist, plist)[0]

                for x, p in zip(xlist, plist):
                    self.assertEqual(y % p, x)
