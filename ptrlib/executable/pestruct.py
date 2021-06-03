from ptrlib.util.construct import *

class PEStructs(object):
    def __init__(self, bits=64):
        self.bits = bits

    def create_basic_structs(self):
        # Register type
        self.BYTE  = Int8ul
        self.WORD  = Int16ul
        self.DWORD = Int32ul
        self.LONG  = Int32ul
        self.ULONGLONG = Int64ul

        # Register structs
        self._create_DATA_DIRECTORY()
        self._create_DOS_HEADER()
        self._create_OPTIONAL_HEADER()
        self._create_NT_HEADERS()
        self._create_SECTION_HEADER()

    def _create_DOS_HEADER(self):
        """Craete MS-DOS header"""
        self.DOS_HEADER = 'DOS_HEADER' / Struct(
            'e_magic' / self.WORD,
            'e_cblp' / self.WORD,
            'e_cp' / self.WORD,
            'e_crlc' / self.WORD,
            'e_cparhdr' / self.WORD,
            'e_minalloc' / self.WORD,
            'e_maxalloc' / self.WORD,
            'e_ss' / self.WORD,
            'e_sp' / self.WORD,
            'e_csum' / self.WORD,
            'e_ip' / self.WORD,
            'e_cs' / self.WORD,
            'e_lfarlc' / self.WORD,
            'e_ovno' / self.WORD,
            'e_res' / Array(4, self.WORD),
            'e_oemid' / self.WORD,
            'e_oeminfo' / self.WORD,
            'e_res2' / Array(10, self.WORD),
            'e_lfanew' / self.LONG
        )

    def _create_OPTIONAL_HEADER(self):
        if self.bits == 32:
            self.OPTIONAL_HEADER = 'OptionalHeader' / Struct (
                'Magic' / self.WORD,
                'MajorLinkerVersion' / self.BYTE,
                'MinorLinkerVersion' / self.BYTE,
                'SizeOfCode' / self.DWORD,
                'SizeOfInitializedData' / self.DWORD,
                'SizeOfUninitializedData' / self.DWORD,
                'AddressOfEntryPoint' / self.DWORD,
                'BaseOfCode' / self.DWORD,
                'BaseOfData' / self.DWORD,
                'ImageBase' / self.DWORD,
                'SectionAlignment' / self.DWORD,
                'FileAlignment' / self.DWORD,
                'MajorOperatingSystemVersion' / self.WORD,
                'MinorOperatingSystemVersion' / self.WORD,
                'MajorImageVersion' / self.WORD,
                'MinorImageVersion' / self.WORD,
                'MajorSubSystemVersion' / self.WORD,
                'MinorSubsystemVersion' / self.WORD,
                'Win32VersionValue' / self.DWORD,
                'SizeOfImages' / self.DWORD,
                'SizeOfHeaders' / self.DWORD,
                'CheckSum' / self.DWORD,
                'Subsystem' / self.WORD,
                'DllCharacteristics' / self.WORD,
                'SizeOfStackReserve' / self.DWORD,
                'SizeOfStackCommit' / self.DWORD,
                'SizeOfHeapReserve' / self.DWORD,
                'SizeOfHeapCommit' / self.DWORD,
                'LoaderFlags' / self.DWORD,
                'NumberOfRvaAndSizes' / self.DWORD,
                'DataDirectory' / Array(this.NumberOfRvaAndSizes,
                                        self.DATA_DIRECTORY)
            )
        else:
            self.OPTIONAL_HEADER = 'OptionalHeader' / Struct (
                'Magic' / self.WORD,
                'MajorLinkerVersion' / self.BYTE,
                'MinorLinkerVersion' / self.BYTE,
                'SizeOfCode' / self.DWORD,
                'SizeOfInitializedData' / self.DWORD,
                'SizeOfUninitializedData' / self.DWORD,
                'AddressOfEntryPoint' / self.DWORD,
                'BaseOfCode' / self.DWORD,
                'ImageBase' / self.ULONGLONG,
                'SectionAlignment' / self.DWORD,
                'FileAlignment' / self.DWORD,
                'MajorOperatingSystemVersion' / self.WORD,
                'MinorOperatingSystemVersion' / self.WORD,
                'MajorImageVersion' / self.WORD,
                'MinorImageVersion' / self.WORD,
                'MajorSubSystemVersion' / self.WORD,
                'MinorSubsystemVersion' / self.WORD,
                'Win32VersionValue' / self.DWORD,
                'SizeOfImages' / self.DWORD,
                'SizeOfHeaders' / self.DWORD,
                'CheckSum' / self.DWORD,
                'Subsystem' / self.WORD,
                'DllCharacteristics' / self.WORD,
                'SizeOfStackReserve' / self.ULONGLONG,
                'SizeOfStackCommit' / self.ULONGLONG,
                'SizeOfHeapReserve' / self.ULONGLONG,
                'SizeOfHeapCommit' / self.ULONGLONG,
                'LoaderFlags' / self.DWORD,
                'NumberOfRvaAndSizes' / self.DWORD,
                'DataDirectory' / Array(this.NumberOfRvaAndSizes,
                                        self.DATA_DIRECTORY)
        )

    def _create_NT_HEADERS(self):
        """Create NT header"""
        self.NT_HEADERS = 'NT_HEADERS' / Struct (
            'Signature' / self.DWORD,
            'FileHeader' / Struct (
                'Machine' / self.WORD,
                'NumberOfSections' / self.WORD,
                'TimeDateStamp' / self.DWORD,
                'PointerToSymbolTable' / self.DWORD,
                'NumberOfSymbols' / self.DWORD,
                'SizeOfOptionalHeader' / self.WORD,
                'Characteristics' / self.WORD
            ),
            'OptionalHeader' / self.OPTIONAL_HEADER
        )

    def _create_DATA_DIRECTORY(self):
        self.DATA_DIRECTORY = 'DATA_DIRECTORY' / Struct(
            'VirtualAddress' / self.DWORD,
            'Size' / self.DWORD
        )

    def _create_SECTION_HEADER(self):
        self.SECTION_HEADER = 'SECTION_HEADER' / Struct(
            'Name' / Array(8, self.BYTE),
            'Misc' / Union(
                0,
                'PhysicalAddress' / self.DWORD,
                'VirtualSize' / self.DWORD
            ),
            'VirtualAddress' / self.DWORD,
            'SizeOfRawData' / self.DWORD,
            'PointerToRawData' / self.DWORD,
            'PointerToRelocations' / self.DWORD,
            'PointerToLinenumbers' / self.DWORD,
            'NumberOfRelocations' / self.WORD,
            'NumberOfLinenumbers' / self.WORD,
            'Characteristics' / self.DWORD,
        )
