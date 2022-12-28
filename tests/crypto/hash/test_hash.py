import unittest
import os
from ptrlib import MD5, SHA1, SHA256, lenext
from hashlib import md5, sha1, sha256
from logging import getLogger, FATAL


class TestHash(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_MD5(self):
        h = MD5()
        h.update(b'a')
        self.assertEqual(md5(b'a').digest(), h.digest())

        m = os.urandom(100)
        h = MD5()
        h.update(m)
        self.assertEqual(md5(m).digest(), h.digest())

    def test_SHA1(self):
        h = SHA1()
        h.update(b'a')
        self.assertEqual(sha1(b'a').digest(), h.digest())

        m = os.urandom(100)
        h = SHA1()
        h.update(m)
        self.assertEqual(sha1(m).digest(), h.digest())

    def test_SHA256(self):
        h = SHA256()
        h.update(b'a')
        self.assertEqual(sha256(b'a').digest(), h.digest())

        m = os.urandom(100)
        h = SHA256()
        h.update(m)
        self.assertEqual(sha256(m).digest(), h.digest())

    def test_lenext(self):
        SALT = os.urandom(8)
        known_message = os.urandom(16)
        append_message = os.urandom(16)

        known_hash = md5(SALT + known_message).hexdigest()
        new_hash, data = lenext(
            MD5, len(SALT), known_hash, known_message, append_message
        )
        self.assertEqual(md5(SALT + data).hexdigest(), new_hash)

        known_hash = sha1(SALT + known_message).hexdigest()
        new_hash, data = lenext(
            SHA1, len(SALT), known_hash, known_message, append_message
        )
        self.assertEqual(sha1(SALT + data).hexdigest(), new_hash)

        known_hash = sha256(SALT + known_message).hexdigest()
        new_hash, data = lenext(
            SHA256, len(SALT), known_hash, known_message, append_message
        )
        self.assertEqual(sha256(SALT + data).hexdigest(), new_hash)
