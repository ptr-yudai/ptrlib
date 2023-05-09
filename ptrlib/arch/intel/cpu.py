from ptrlib.binary.encoding import bit_reflect
from ptrlib.binary.packing import u64


def intel_crc32(crc: int, data: bytes):
    """Emulate CRC32 instruction
    """
    def mod2(x, mod):
        while x.bit_length() >= mod.bit_length():
            x ^= mod << (x.bit_length() - mod.bit_length())
        return x

    if not isinstance(crc, int) or not 0 <= crc <= 0xffffffff:
        raise ValueError(f"Initial value must be {bits}-bit positive integer")

    if len(data) == 1:
        bits = 8
    elif len(data) == 2:
        bits = 16
    elif len(data) == 4:
        bits = 32
    elif len(data) == 8:
        bits = 64
    else:
        raise ValueError("Data must be either 1, 2, 4, or 8 bytes long")

    t1 = bit_reflect(u64(data), bits)
    t2 = bit_reflect(crc, 32)
    t6 = mod2((t1 << 32) ^ (t2 << bits), 0x11edc6f41)

    return bit_reflect(t6, 32)
