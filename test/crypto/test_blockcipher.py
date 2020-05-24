import unittest
import os
from logging import getLogger, FATAL
from ptrlib.crypto.ecb import *
from ptrlib.crypto.padcbc import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class TestBlockCipher(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_ecb_chosenplaintext(self):
        prefix = os.urandom(40)
        flag = os.urandom(30)
        key = sha256(flag).digest()
        aes = AES.new(key, AES.MODE_ECB)

        def encrypt(m):
            return aes.encrypt(pad(prefix + m + flag, AES.block_size))

        self.assertEqual(flag, ecb_chosenplaintext(encrypt, prefix, len(flag)))

    def test_padding_oracle(self):
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
        self.assertEqual(m, padding_oracle(try_decrypt, c, iv=iv, bs=AES.block_size))

    def test_padding_oracle_attack(self):
        key = os.urandom(AES.block_size)

        def try_decrypt(c):
            try:
                aes = AES.new(key, AES.MODE_CBC, iv=c[:AES.block_size])
                unpad(aes.decrypt(c[AES.block_size:]), AES.block_size)
                return True
            except:
                return False

        m = pad(os.urandom(50), AES.block_size)
        iv, c = padding_oracle_encrypt(try_decrypt, m, bs=AES.block_size)
        aes = AES.new(key, AES.MODE_CBC, iv=iv)
        self.assertEqual(m, aes.decrypt(c))
