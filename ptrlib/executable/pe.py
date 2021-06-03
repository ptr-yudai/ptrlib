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

        self.set_base()

    def symbol(self, name):
        """Get the address of a symbol

        Find the address corresponding to the given symbol.

        Args:
            name (str): The sybmol name to find

        Returns:
            int: The address of the symbol
        """
        if isinstance(name, str):
            name = str2bytes(name)

        # Find symbol
        raise NotImplementedError()

    def find(self, pattern, stream_pos=0):
        """Alias of ```search```"""
        for result in self.search(pattern, stream_pos):
            yield result

    def search(self, pattern, stream_pos=0):
        """Find a binary data from the ELF

        Args:
            pattern (bytes): A data to find

        Returns:
            generator: Address
        """
        if isinstance(pattern, str):
            pattern = str2bytes(pattern)

        # Find pattern
        raise NotImplementedError()

    def section(self, name):
        """Get the address of a section by name

        Lookup and find a section by name and return the address.

        Args:
            name (str): The section name to find

        Returns:
            int: The address of the section
        """
        if isinstance(name, str):
            name = str2bytes(name)

        raise NotImplementedError()

    def got(self, name):
        """Alias of ```iat``` for Linux pwners"""
        return self.iat(name)

    def plt(self, name):
        """Alias of ```function``` for Linux pwners"""
        return self.func(name)

    def iat(self, name):
        """Get the address of an IAT entry

        Lookup the IAT entries and find the corresponding address.

        Args:
            name (str): The function name to find

        Returns:
            int: The address of the IAT entry
        """
        if isinstance(name, str):
            name = str2bytes(name)

        raise NotImplementedError()

    def func(self, name):
        """Get the address of an IAT caller

        Find the address of the corresponding IAT caller.

        Args:
            name (str): The function name to find

        Returns:
            int: The address of the function caller
        """
        if isinstance(name, str):
            name = str2bytes(name)

        raise NotImplementedError()

    def eat(self, name):
        """Get the address of an EAT entry

        Lookup the EAT entries and find the corresponding address.

        Args:
            name (str): The function name to find

        Returns:
            int: The address of the EAT entry
        """
        if isinstance(name, str):
            name = str2bytes(name)

        raise NotImplementedError()

    def set_base(self, base=None):
        """Set the load address

        Args:
            int: The base address to be used
        """
        self._base = base

    @property
    def base(self):
        """Get the load address

        Returns:
            int: The address where the PE is loaded
        """
        return self._base

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
