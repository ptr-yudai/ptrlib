import unittest
from logging import getLogger, FATAL
from ptrlib import lsb_leak_attack
from Crypto.Util.number import *


class TestRSA(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_lsb_leak_attack(self):
        for _ in range(2):
            p, q = getPrime(512), getPrime(512)
            n = p * q
            m = getRandomInteger(512)
            e = 65537
            d = inverse(e, (p-1)*(q-1))
            c = pow(m, e, n)

            def oracle(c):
                return pow(c, d, n) & 1

            self.assertEqual(m, lsb_leak_attack(oracle, n, e, c))
