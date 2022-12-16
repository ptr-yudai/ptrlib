import unittest
import os
from logging import getLogger, FATAL
from ptrlib import ecb_chosenplaintext
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class TestEcbChosenPlaintext(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_ecb_chosenplaintext(self):
        for _ in range(10):
            prefix = os.urandom(40)
            flag = os.urandom(30)
            key = sha256(flag).digest()
            aes = AES.new(key, AES.MODE_ECB)

            def encrypt(m):
                return aes.encrypt(pad(prefix + m + flag, AES.block_size))

            self.assertEqual(flag, ecb_chosenplaintext(encrypt, prefix, len(flag)))
