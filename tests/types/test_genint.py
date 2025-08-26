import random
import unittest
from ptrlib import GeneratorOrInt
from logging import getLogger, FATAL


class TestGeneratorOrInt(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_int(self):
        def f(s: int, e: int):
            for i in range(s, e):
                yield i
        s = random.randint(-0xffffffff, 0)
        e = random.randint(s + 0x10, 0xffffffff)
        g = GeneratorOrInt(f(s, e), f'f({s}, {e})'.encode())

        self.assertEqual(int(g), s)

        delta = random.randint(1, 32)
        self.assertEqual(g + delta, s + delta)
        self.assertEqual(g - delta, s - delta)
        self.assertEqual(g // delta, s // delta)
        self.assertEqual(g / delta, s / delta)
        self.assertEqual(g * delta, s * delta)
        self.assertEqual(g >> delta, s >> delta)
        self.assertEqual(g << delta, s << delta)
        self.assertEqual(g & delta, s & delta)
        self.assertEqual(g | delta, s | delta)
        self.assertEqual(g ^ delta, s ^ delta)
        self.assertEqual(g % delta, s % delta)
        self.assertEqual(g ** 2, s ** 2)
        self.assertEqual(pow(g, 2, 0xffff), pow(s, 2, 0xffff))

        self.assertEqual(g[0] + delta, s + delta)
        self.assertEqual(g[1] + delta, s + delta + 1)
        self.assertEqual(g[2] + delta, s + delta + 2)
        self.assertEqual(g[2] * delta, (s + 2) * delta)
        self.assertEqual(g[2] << delta, (s + 2) << delta)
        self.assertEqual(g[2] ^ delta, (s + 2) ^ delta)

        self.assertTrue(g == s)
        self.assertTrue(g != s + 1)
        self.assertTrue(g > s - 1)
        self.assertTrue(g < s + 1)
        self.assertTrue(g >= s)
        self.assertTrue(g <= s)

    def test_generator(self):
        def f(s: int, e: int):
            for i in range(s, e):
                yield i
        s = random.randint(-0xffffffff, 0)
        e = random.randint(s + 0x10, 0xffffffff)
        g = GeneratorOrInt(f(s, e), f'f({s}, {e})'.encode())

        self.assertEqual(g[0], s)
        self.assertEqual(g[1], s + 1)
        self.assertEqual(g[2], s + 2)

        for i in range(10):
            self.assertEqual(g, s)
            self.assertEqual(next(g), s + i)

        self.assertEqual(g[0], s)
        self.assertEqual(g[1], s + 1)
        self.assertEqual(g[2], s + 2)
