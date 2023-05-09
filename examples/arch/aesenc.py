from ptrlib import *

dat = b'\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11'
key = b'\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00'

print("[ SIMD.AESENC ]")
enc = simd_aesenc(dat, key)
print(f"key: {key.hex()}")
print(f"dat: {dat.hex()}")
print(f"enc: {enc.hex()}")
dec = simd_aesenc_inv(enc, key)
print(f"dec: {dec.hex()}")

print("[ SIMD.AESDEC ]")
dec = simd_aesdec(dat, key)
print(f"key: {key.hex()}")
print(f"dat: {dat.hex()}")
print(f"dec: {dec.hex()}")
enc = simd_aesdec_inv(dec, key)
print(f"enc: {enc.hex()}")
