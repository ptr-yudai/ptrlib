import unittest
from logging import getLogger, FATAL
from ptrlib import common_modulus_attack
from Crypto.Util.number import *


class TestRSA(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_common_modulus_attack(self):
        for _ in range(10):
            p, q = getPrime(512), getPrime(512)
            n = p * q
            m = getRandomInteger(512)
            e1 = 65537
            e2 = 65539

            c1 = pow(m, e1, n)
            c2 = pow(m, e2, n)

            self.assertEqual(m, common_modulus_attack((c1, c2), (e1, e2), n))
