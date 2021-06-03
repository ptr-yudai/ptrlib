from ptrlib.console.color import Color
from ptrlib.util.encoding import *
from ptrlib.util.packing import *
from ptrlib.executable.pestruct import *
from logging import getLogger
import re

logger = getLogger(__name__)

class PE(object):
    def __init__(self, filepath):
        """PE Parser
        """
        self.filepath = filepath
        self.stream = open(filepath, 'rb')
        if not self._identify():
            raise ValueError("Not a valid PE file")

        # Register PE structs
        self.structs = PEStructs(self.bits)
        self.structs.create_basic_structs()

        # Parse DOS and NT headers
        self.DOS_HEADER = self._parse(self.structs.DOS_HEADER, stream_pos=0)
        self.NT_HEADERS = self._parse(
            self.structs.NT_HEADERS,
            stream_pos=self.DOS_HEADER.e_lfanew
        )
        sizeof_NT_HEADERS = (0x78 if self.bits == 32 else 0x88) + self.NT_HEADERS.OptionalHeader.NumberOfRvaAndSizes * self.structs.DATA_DIRECTORY.sizeof()

        # Parse section table
        self.SectionTables = []
        for i in range(self.NT_HEADERS.FileHeader.NumberOfSections):
            self.SectionTables.append(self._parse(
                self.structs.SECTION_HEADER,
                stream_pos=self.DOS_HEADER.e_lfanew + sizeof_NT_HEADERS
            ))
            print(self.SectionTables[-1].Name)

    def _identify(self):
        """Check the endian and class of the PE
        """
        # Check DOS header
        self.stream.seek(0)
        signature = self.stream.read(2)
        if signature != b'MZ':
            logger.warning("Invalid DOS header")
            return False

        # Check NT header (PE header)
        self.stream.seek(0x3c)
        self.offset_peh = u32(self.stream.read(4))
        self.stream.seek(self.offset_peh)
        signature = self.stream.read(4)
        if signature != b'PE\0\0':
            logger.warning("Invalid PE header")
            return False

        # Check machine info
        self.stream.seek(self.offset_peh + 4, 1)
        machine = u16(self.stream.read(2))
        if machine == 0x014c:
            self.bits = 32
        elif machine == 0x8664:
            self.bits = 64
        else:
            # Use characteristics as fallback
            self.stream.seek(self.offset_peh + 0x16)
            if u16(self.stream.read(2)) & 0x0100:
                self.bits = 32
            else:
                self.bits = 64

        return True

    def _parse(self, struct, stream_pos=None):
        try:
            if stream_pos is not None:
                self.stream.seek(stream_pos)
            return struct.parse_stream(self.stream)
        except ConstructError as e:
            logger.warning("Parse Error")
            raise e from None

    @property
    def is_dll(self):
        # IMAGE_FILE_DLL
        self.NT_HEADERS.FileHeader.Characteristics & 0x2000

    @property
    def machine(self):
        # IMAGE_FILE_MACHINE_XXXX
        if self.NT_HEADERS.FileHeader.Machine == 0x014c:
            return 'x86'
        elif self.NT_HEADERS.FileHeader.Machine == 0x0200:
            return 'Intel Itanium'
        elif self.NT_HEADERS.FileHeader.Machine == 0x8664:
            return 'x64'
        else:
            return 'unknown'
