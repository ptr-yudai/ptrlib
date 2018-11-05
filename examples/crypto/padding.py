#!/usr/bin/env python
from ptrlib import *

text = "Hello, World!"
bs = 8

padded_text = pad(text, bs)
print("===== PKCS =====")
print("Padded   : " + repr(padded_text))
print("Unpadded : " + repr(unpad(padded_text)))

padded_text = pad(text, bs, 'ANSI')
print("===== ANSI =====")
print("Padded   : " + repr(padded_text))
print("Unpadded : " + repr(unpad(padded_text, 'ANSI')))

padded_text = pad(text, bs, 'ISO')
print("===== ISO =====")
print("Padded   : " + repr(padded_text))
print("Unpadded : " + repr(unpad(padded_text, 'ISO')))

padded_text = pad(text, bs, 'ZERO')
print("===== ZERO =====")
print("Padded   : " + repr(padded_text))
print("Unpadded : " + repr(unpad(padded_text, 'ZERO')))

padded_text = pad(text, bs, 'OAZP')
print("===== OAZP =====")
print("Padded   : " + repr(padded_text))
print("Unpadded : " + repr(unpad(padded_text, 'OAZP')))

padded_text = pad(text, bs, char='?')
print("===== Arbitary Padding =====")
print("Padded   : " + repr(padded_text))
print("Unpadded : " + repr(unpad(padded_text, char='?')))
