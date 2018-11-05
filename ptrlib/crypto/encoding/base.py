"""Base16/32/64/85 Encoder/Decoder"""
import base64
from ..utils import *

def base64encode(data, altchars=None):
    return base64.b64encode(data, altchars=altchars)

def base64decode(data, altchars=None):
    return base64.b64decode(data, altchars=altchars)

def base32encode(data):
    return base64.b32encode(data)

def base32decode(data, casefold=True, map01=None):
    return base64.b32decode(data, casefold=casefold, map01=map01)

def base16encode(data):
    return base64.b16encode(data)

def base16decode(data, casefold=True):
    return base64.b16decode(data, casefold=casefold)

def base85encode(data):
    output = ""
    r = 4 - (len(data) % 4)
    data = pad(data, 4, protocol='ZERO')
    for i in xrange(0, len(data), 4):
        value = u32b(data[i:i+4])
        temp = ""
        for x in range(5):
            temp += chr((value % 85) + 33)
            value //= 85
        output += temp[::-1]
    return output[:-r]
            
def base85decode(data):
    output = ""
    r = 5 - (len(data) % 5)
    data = pad(data, 5, char='u')
    for i in xrange(0, len(data), 5):
        value = 0
        for c in data[i:i+5]:
            value += ord(c) - 33
            value *= 85
        value //= 85
        output += p32b(value)
    return output[:-r]
