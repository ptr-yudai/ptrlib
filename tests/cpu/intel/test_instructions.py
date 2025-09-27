import os
import unittest
from logging import getLogger, FATAL
from ptrlib.cpu import CPU


class TestIntelInstructions(unittest.TestCase):
    """Tests for Intel-specific instructions
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_aes(self):
        """Test AES instruction
        """
        cpu = CPU('intel', 64)

        dat = b'\x00\xff\xee\xdd\xcc\xbb\xaa\x99'\
            b'\x88\x77\x66\x55\x44\x33\x22\x11'
        key = b'\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08'\
            b'\x07\x06\x05\x04\x03\x02\x01\x00'
        enc = b'\x5d\x75\x7f\x6f\xcb\xdf\xd2\x2a'\
            b'\x0c\xc9\x7b\x7f\x5f\x26\x50\x74'
        dec = b'\xe9\xbd\x56\x1c\x42\xe8\xb5\x3c'\
            b'\xf1\xc9\xdb\xf0\x67\x8d\xdf\x1a'

        self.assertEqual(cpu.instruction.aesenc(dat, key), enc)
        self.assertEqual(cpu.instruction.aesdec(dat, key), dec)
        for _ in range(10):
            dat = os.urandom(16)
            key = os.urandom(16)
            self.assertEqual(cpu.instruction.aesenc_inv(cpu.instruction.aesenc(dat, key), key), dat)
            self.assertEqual(cpu.instruction.aesdec_inv(cpu.instruction.aesdec(dat, key), key), dat)
