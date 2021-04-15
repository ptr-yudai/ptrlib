import unittest
import random
from ptrlib import random_bool, random_str, random_int, random_float, random_bytes, random_list, random_dict
from logging import getLogger, FATAL

class TestELF(unittest.TestCase):
    def setUp(self):
        self.MAX_ROUND = 1000
        getLogger("ptrlib").setLevel(FATAL)

    def test_bool(self):
        history = []
        for i in range(self.MAX_ROUND):
            v = random_bool(true_p=0.75)
            self.assertTrue(v in [True, False])
            history.append(v)

        self.assertTrue(False in history)
        self.assertTrue(history.count(True) > self.MAX_ROUND // 2)

    def test_str(self):
        charset = [chr(c) for c in range(0x100)]
        for i in range(self.MAX_ROUND):
            table = ''.join(random.sample(charset, 0x80))
            lmin = random.randint(0, 100)
            lmax = random.randint(lmin, 100)
            v = random_str(lmin, lmax, charset=table)
            self.assertTrue(lmin <= len(v) <= lmax)
            self.assertTrue(all([c in table for c in v]))

    def test_int(self):
        for i in range(self.MAX_ROUND):
            lmin = random.randint(-0xffffffff, 0xffffffff)
            lmax = random.randint(lmin, 0xffffffff)
            v = random_int(lmin, lmax)
            self.assertTrue(lmin <= v <= lmax)

    def test_float(self):
        for i in range(self.MAX_ROUND):
            lmin = random.uniform(-0xffffffff, 0xffffffff)
            lmax = random.uniform(lmin, 0xffffffff)
            v = random_float(lmin, lmax)
            self.assertTrue(lmin <= v <= lmax)

    def test_bytes(self):
        charset = [c for c in range(0x100)]
        for i in range(self.MAX_ROUND):
            table = random.sample(charset, 0x80)
            lmin = random.randint(0, 100)
            lmax = random.randint(lmin, 100)
            v = random_bytes(lmin, lmax, charset=table)
            self.assertTrue(lmin <= len(v) <= lmax)
            self.assertTrue(all([c in table for c in v]))
