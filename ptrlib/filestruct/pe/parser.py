import functools
from .structs import *

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


class PEParser(object):
    def __init__(self, filepath):
        self.stream = open(filepath, 'rb')

        # Parse IMAGE_DOS_HEADER
        self.doshdr = IMAGE_DOS_HEADER().parse_stream(self.stream)
        if self.doshdr['e_magic'] != 0x5A4D:
            raise ValueError("Not a valid PE file")

        if self.doshdr['e_lfanew'] > IMAGE_DOS_HEADER().size:
            self.stub_program = self.stream.read(
                self.doshdr['e_lfanew'] - IMAGE_DOS_HEADER().size
            )

        # Parse IMAGE_NT_HEADER
        self.stream.seek(self.doshdr['e_lfanew'])
        self.nthdr = IMAGE_NT_HEADER().parse_stream(self.stream)
        if self.nthdr['OptionalHeader']['Magic'] == 0x20b:
            # PE+
            self.bits = 64
        elif self.nthdr['OptionalHeader']['Magic'] == 0x10b or \
             self.nthdr['OptionalHeader']['Magic'] == 0x107:
            # PE32 or ROM
            self.bits = 32
        else:
            logger.error("Invalid Magic in IMAGE_NT_HEADER.OptionalHeader")
