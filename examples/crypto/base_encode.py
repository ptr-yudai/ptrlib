#!/usr/bin/env python
from ptrlib import *

text = 'Hello, World!'

encoded_text = base64encode(text)
print("===== Base64 =====")
print("Encoded: " + encoded_text)
print("Decoded: " + base64decode(encoded_text))

encoded_text = base16encode(text)
print("===== Base16 =====")
print("Encoded: " + encoded_text)
print("Decoded: " + base16decode(encoded_text))

encoded_text = base32encode(text)
print("===== Base32 =====")
print("Encoded: " + encoded_text)
print("Decoded: " + base32decode(encoded_text))

encoded_text = base85encode(text)
print("===== Base85 =====")
print("Encoded: " + encoded_text)
print("Decoded: " + base85decode(encoded_text))
