from binascii import crc32


def rev_crc32(bs: bytes, target: int) -> bytes:
    target = target ^ 0xFFFFFFFF

    inv = 0x5B358FD3
    key = 0xEDB88320
    crc = crc32(bs) ^ 0xFFFFFFFF

    new = 0
    for _ in range(32):
        if new & 1:
            new = (new >> 1) ^ key
        else:
            new = new >> 1
        if target & 1:
            new = new ^ inv
        target = target >> 1
    return (new ^ crc).to_bytes(4, "little")
