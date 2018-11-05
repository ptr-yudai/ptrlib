import random
import struct

def p8(value) : return struct.pack('<B', value)
def u8(data)  : return struct.unpack('<B', data)[0]
def p16(value): return struct.pack('<H', value)
def u16(data) : return struct.unpack('<H', data)[0]
def p32(value): return struct.pack('<I', value)
def u32(data) : return struct.unpack('<I', data)[0]
def p64(value): return struct.pack('<Q', value)
def u64(data) : return struct.unpack('<Q', data)[0]
def p8b(value) : return struct.pack('>B', value)
def u8b(data)  : return struct.unpack('>B', data)[0]
def p16b(value): return struct.pack('>H', value)
def u16b(data) : return struct.unpack('>H', data)[0]
def p32b(value): return struct.pack('>I', value)
def u32b(data) : return struct.unpack('>I', data)[0]
def p64b(value): return struct.pack('>Q', value)
def u64b(data) : return struct.unpack('>Q', data)[0]

def pad(data, bs, protocol='PKCS', char=None):
    """ Append a padding characters
    You can choose `protocols` from the following list:
    - PKCS (PKCS#5, PKCS#7)
        If the block size is B, then add N padding bytes of value N
        to make the input length up to the next exact multiple of B.
    - ANSI (ANSI X.923)
        If the block size is B, then add N-1 null bytes and 1 byte of
        value N to make the input length up to the next exact multiple of B.
    - ISO, W3C (ISO 10126)
        Random bytes are added and the padding boundary is specified
        by the last byte.
    - ZERO (Zero padding)
        Null bytes are added to make the input length up to the next
        exact multiple of the block size.
    - OAZP (OneAndZeros Padding)
        A byte of value 0x80 is added, followed by as many null bytes as is
        necessary to fill the input length up to the next exact multiple of B.

    If you set a character to `char`, some bytes of the value `char`
    are appended to fill the input length up to the multiple of `bs`.
    """
    p = protocol.upper()
    if char:
        if len(char) != 1:
            raise ValueError("Padding character must be 1 byte")
        return data + char * (bs - (len(data) % bs))
    elif p == 'PKCS':
        return data + chr(bs - (len(data) % bs)) * (bs - (len(data) % bs))
    elif p == 'ANSI':
        return data + '\x00' * ((bs - (len(data) % bs) - 1) % bs) + chr(bs - (len(data) % bs))
    elif p == 'ISO' or p == 'W3C':
        return data + ''.join([chr(random.randint(0, 255)) for i in xrange((bs - (len(data) % bs) - 1) % bs)]) + chr(bs - (len(data) % bs))
    elif p == 'ZERO':
        return data + '\x00' * (bs - (len(data) % bs))
    elif p == 'OAZP':
        return data + '\x80' + '\x00' * ((bs - (len(data) % bs) - 1) % bs)
    raise ValueError("Invalid padding protocol specified")

def unpad(s, protocol='PKCS', char=None):
    """ Get rid of padding characters
    The keyword `protocols` is same as that of `pad` function.
    """
    p = protocol.upper()
    if char:
        if len(char) != 1:
            raise ValueError("Padding character must be 1 byte")
        return s.rstrip(char)
    elif p == 'PKCS' or p == 'ANSI' or p == 'ISO':
        return s[:-ord(s[-1])]
    elif p == 'ZERO':
        return s.rstrip('\x00')
    elif p == 'OAZP':
        return s.rstrip('\x00')[:-1]
    raise ValueError("Invalid padding protocol specified")
