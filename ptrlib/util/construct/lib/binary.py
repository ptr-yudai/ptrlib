from ptrlib.util.construct.lib.py3compat import *
import binascii


def integer2bits(number, width):
    r"""
    Converts an integer into its binary representation in a bit-string. Width is the amount of bits to generate. If width is larger than the actual amount of bits required to represent number in binary, sign-extension is used. If it's smaller, the representation is trimmed to width bits. Each bit is represented as either \\x00 or \\x01. The most significant is first, big-endian. This is reverse to `bits2integer`.

    Examples:

        >>> integer2bits(19, 8)
        b'\x00\x00\x00\x01\x00\x00\x01\x01'
    """
    if width < 0:
        raise ValueError("width must be non-negative")
    number = int(number)
    if number < 0:
        number += 1 << width
    bits = [b"\x00"] * width
    i = width - 1
    while number and i >= 0:
        bits[i] = int2byte(number & 1)
        number >>= 1
        i -= 1
    return b"".join(bits)


def integer2bytes(number, width):
    r"""
    Converts a bytes-string into an integer. This is reverse to `bytes2integer`.

    Examples:

        >>> integer2bytes(19,4)
        '\x00\x00\x00\x13'
    """
    if width < 0:
        raise ValueError("width must be non-negative")
    number = int(number)
    if number < 0:
        number += 1 << (width * 8)
    acc = [b"\x00"] * width
    i = width - 1
    while number > 0:
        acc[i] = int2byte(number & 255)
        number >>= 8
        i -= 1
    return b"".join(acc)


def bits2integer(data, signed=False):
    r"""
    Converts a bit-string into an integer. Set sign to interpret the number as a 2-s complement signed integer. This is reverse to `integer2bits`.

    Examples:

        >>> bits2integer(b"\x01\x00\x00\x01\x01")
        19
    """
    number = 0
    for b in iterateints(data):
        number = (number << 1) | b

    if signed and byte2int(data[0:1]):
        bias = 1 << len(data)
        return number - bias
    else:
        return number


def bytes2integer(data, signed=False):
    r"""
    Converts a byte-string into an integer. This is reverse to `integer2bytes`.

    Examples:

        >>> bytes2integer(b'\x00\x00\x00\x13')
        19
    """
    number = 0
    for b in iterateints(data):
        number = (number << 8) | b

    if signed and byte2int(bytes2bits(data[0:1])[0:1]):
        bias = 1 << len(data)*8
        return number - bias
    else:
        return number


BYTES2BITS_CACHE = {i:integer2bits(i,8) for i in range(256)}
def bytes2bits(data):
    r""" 
    Converts between bit and byte representations in b-strings.

    Example:

        >>> bytes2bits(b'ab')
        b"\x00\x01\x01\x00\x00\x00\x00\x01\x00\x01\x01\x00\x00\x00\x01\x00"
    """
    return b"".join(BYTES2BITS_CACHE[b] for b in iterateints(data))


BITS2BYTES_CACHE = {bytes2bits(int2byte(i)):int2byte(i) for i in range(256)}
def bits2bytes(data):
    r""" 
    Converts between bit and byte representations in b-strings.

    Example:

        >>> bits2bytes(b"\x00\x01\x01\x00\x00\x00\x00\x01\x00\x01\x01\x00\x00\x00\x01\x00")
        b'ab'
    """
    if len(data) & 7:
        raise ValueError("data length must be a multiple of 8")
    return b"".join(BITS2BYTES_CACHE[data[i:i+8]] for i in range(0,len(data),8))


def swapbytes(data):
    r"""
    Performs an endianness swap on byte-string.

    Example:

        >>> swapbytes(b'abcd')
        b'dcba'
    """
    return data[::-1]


def swapbytesinbits(data):
    r"""
    Performs an byte-swap within a bit-string. Its length must be multiple of 8.

    Example:

        >>> swapbytesinbits(b'0000000011111111')
        b'1111111100000000'
    """
    if len(data) & 7:
        raise ValueError("data length must be multiple of 8")
    return b"".join(data[i:i+8] for i in reversed(range(0,len(data),8)))


SWAPBITSINBYTES_CACHE = {i:bits2bytes(bytes2bits(int2byte(i))[::-1]) for i in range(256)}
def swapbitsinbytes(data):
    r"""
    Performs a bit-reversal within a byte-string.

    Example:

        >>> swapbits(b'\xf0')
        b'\x0f'
    """
    return b"".join(SWAPBITSINBYTES_CACHE[b] for b in iterateints(data))


def hexlify(data):
    """Returns binascii.hexlify(data)."""
    return binascii.hexlify(data)


def unhexlify(data):
    """Returns binascii.unhexlify(data)."""
    return binascii.unhexlify(data)
