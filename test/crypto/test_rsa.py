import unittest
from logging import getLogger, FATAL
from ptrlib.crypto.rsa import *
from Crypto.Util.number import *

class TestRSA(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_common_modulus_attack(self):
        p, q = getPrime(512), getPrime(512)
        n = p * q
        m = getRandomInteger(512)
        e1 = 65537
        e2 = 65539

        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)

        self.assertEqual(m, common_modulus_attack((c1, c2), (e1, e2), n))

    def test_lsb_leak_attack(self):
        p, q = getPrime(512), getPrime(512)
        n = p * q
        m = getRandomInteger(512)
        e = 65537
        d = inverse(e, (p-1)*(q-1))
        c = pow(m, e, n)

        def oracle(c):
            return pow(c, d, n) & 1

        self.assertEqual(m, lsb_leak_attack(oracle, n, e, c))
