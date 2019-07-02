from ptrlib import rev_crc32
from binascii import crc32

x = b"takoyakitabetai"
y = crc32(x)
t = rev_crc32(x, 0xCAFEBABE)
z = crc32(x + t)
print("crc32({}) = 0x{:0X}".format(x, y))
print("crc32({}) = 0x{:0X}".format(x + t, z))
