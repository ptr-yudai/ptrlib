import functools
from ptrlib.filestruct.bunkai import *

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache

BYTE  = u8
WORD  = u16
DWORD = LONG = u32


@cache
def IMAGE_DOS_HEADER():
    return 'IMAGE_DOS_HEADER' <= Struct(
        'e_magic'    <= WORD,
        'e_cblp'     <= WORD,
        'e_cp'       <= WORD,
        'e_crlc'     <= WORD,
        'e_cparhdr'  <= WORD,
        'e_minalloc' <= WORD,
        'e_maxalloc' <= WORD,
        'e_ss'       <= WORD,
        'e_sp'       <= WORD,
        'e_csum'     <= WORD,
        'e_ip'       <= WORD,
        'e_cs'       <= WORD,
        'e_lfarlc'   <= WORD,
        'e_ovno'     <= WORD,
        'e_res'      <= Array(4, WORD),
        'e_oemid'    <= WORD,
        'e_oeminfo'  <= WORD,
        'e_res2'     <= Array(10, WORD),
        'e_lfanew'   <= LONG
    )

@cache
def IMAGE_FILE_HEADER():
    return Struct(
        'Machine'              <= WORD,
        'NumberOfSections'     <= WORD,
        'TimeDateStamp'        <= DWORD,
        'PointerToSymbolTable' <= DWORD,
        'NumberOfSymbols'      <= DWORD,
        'SizeOfOptionalHeader' <= WORD,
        'Characteristics'      <= WORD
    )

@cache
def IMAGE_DATA_DIRECTORY():
    return Struct(
        'VirtualAddress' <= DWORD,
        'Size' <= DWORD
    )

@cache
def IMAGE_OPTIONAL_HEADER():
    return Struct(
        # Standerd fields
        'Magic' <= WORD,
        'MajorLinkerVersion' <= BYTE,
        'MinorLinkerVersion' <= BYTE,
        'SizeOfCode'              <= DWORD,
        'SizeOfInitializedData'   <= DWORD,
        'SizeOfUninitializedData' <= DWORD,
        'AddressOfEntryPoint'     <= DWORD,
        'BaseOfCode'              <= DWORD,
        'BaseOfData'              <= DWORD,
        # NT additional fields
        'ImageBase'        <= DWORD,
        'SectionAlignment' <= DWORD,
        'FileAlignment'    <= DWORD,
        'MajorOperatingSystemVersion' <= WORD,
        'MinorOperatingSystemVersion' <= WORD,
        'MajorImageVersion'           <= WORD,
        'MinorImageVersion'           <= WORD,
        'MajorSubsystemVersion'       <= WORD,
        'MinorSubsystemVersion'       <= WORD,
        'Win32VersionValue'           <= DWORD,
        'SizeOfImage'   <= DWORD,
        'SizeOfHeaders' <= DWORD,
        'CheckSum'  <= DWORD,
        'Subsystem' <= WORD,
        'DllCharacteristics' <= WORD,
        'SizeOfStackReserve' <= DWORD,
        'SizeOfStackCommit'  <= DWORD,
        'SizeOfHeapReserve'  <= DWORD,
        'SizeOfHeapCommit'   <= DWORD,
        'LoaderFlags' <= DWORD,
        'NumberOfRvaAndSizes' <= DWORD,
        'DataDirectories' <= Array(16, IMAGE_DATA_DIRECTORY()),
        '' <= Array(16, u8)
    )

@cache
def IMAGE_NT_HEADER():
    return 'IMAGE_NT_HEADER' <= Struct(
        'Signature' <= DWORD,
        'FileHeader' <= IMAGE_FILE_HEADER(),
        'OptionalHeader' <= IMAGE_OPTIONAL_HEADER()
    )

@cache
def IMAGE_SECTION_HEADER():
    return 'IMAGE_SECTION_HEADER' <= Struct(
        'Name' <= Array(8, BYTE),
        'Misc' <= Union(
            'PhysicalAddress' <= DWORD,
            'VirtualSize'     <= DWORD,
        ),
        'VirtualAddress' <= DWORD,
        'SizeOfRawData'  <= DWORD,
        'PointerToRawData'     <= DWORD,
        'PointerToRelocations' <= DWORD,
        'PointerToLinenumbers' <= DWORD,
        'NumberOfRelocations' <= DWORD,
        'NumberOfLinenumbers' <= DOWRD,
        'Characteristics' <= DWORD,
    )
