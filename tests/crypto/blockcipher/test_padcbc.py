import unittest
import os
from logging import getLogger, FATAL
from ptrlib.crypto import padding_oracle, padding_oracle_encrypt
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class TestPaddingOracle(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_padding_oracle(self):
        ok_count = 0
        for _ in range(10):
            iv = os.urandom(AES.block_size)
            key = os.urandom(AES.block_size)
            aes = AES.new(key, AES.MODE_CBC, iv=iv)
            m = pad(os.urandom(50), AES.block_size)
            c = aes.encrypt(m)

            def try_decrypt(c):
                try:
                    aes = AES.new(key, AES.MODE_CBC, iv=c[:AES.block_size])
                    unpad(aes.decrypt(c[AES.block_size:]), AES.block_size)
                    return True
                except:
                    return False

            try:
                if m == padding_oracle(try_decrypt, c, iv=iv, bs=AES.block_size):
                    ok_count += 1
            except ValueError:
                pass

        self.assertTrue(ok_count > 7)

    def test_padding_oracle_attack(self):
        ok_count = 0
        for _ in range(10):
            key = os.urandom(AES.block_size)

            def try_decrypt(c):
                try:
                    aes = AES.new(key, AES.MODE_CBC, iv=c[:AES.block_size])
                    unpad(aes.decrypt(c[AES.block_size:]), AES.block_size)
                    return True
                except:
                    return False

            m = pad(os.urandom(50), AES.block_size)
            try:
                iv, c = padding_oracle_encrypt(try_decrypt, m, bs=AES.block_size)
                aes = AES.new(key, AES.MODE_CBC, iv=iv)
                if m == aes.decrypt(c):
                    ok_count += 1
            except ValueError:
                pass

        self.assertTrue(ok_count > 7)
