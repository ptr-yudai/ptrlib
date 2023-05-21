import functools
from ptrlib.filestruct.bunkai import *

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache

BYTE  = u8
WORD  = u16
DWORD = LONG = u32
ULONGLONG = u64
SHORT = s16

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
def IMAGE_OPTIONAL_HEADER_MAGIC():
    return 'Magic' <= WORD

@cache
def IMAGE_OPTIONAL_HEADER(parser):
    if parser.bits == 32:
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
        )
    else:
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
            # NT additional fields
            'ImageBase'        <= ULONGLONG,
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
            'SizeOfStackReserve' <= ULONGLONG,
            'SizeOfStackCommit'  <= ULONGLONG,
            'SizeOfHeapReserve'  <= ULONGLONG,
            'SizeOfHeapCommit'   <= ULONGLONG,
            'LoaderFlags' <= DWORD,
            'NumberOfRvaAndSizes' <= DWORD,
            'DataDirectories' <= Array(16, IMAGE_DATA_DIRECTORY()),
        )

@cache
def IMAGE_NT_HEADER(parser):
    return 'IMAGE_NT_HEADER' <= Struct(
        'Signature' <= DWORD,
        'FileHeader' <= IMAGE_FILE_HEADER(),
        'OptionalHeader' <= IMAGE_OPTIONAL_HEADER(parser)
    )

@cache
def IMAGE_SECTION_HEADER(parser):
    if parser.bits == 32:
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
            'NumberOfRelocations' <= WORD,
            'NumberOfLinenumbers' <= WORD,
            'Characteristics' <= DWORD,
        )
    else:
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
            'NumberOfRelocations' <= WORD,
            'NumberOfLinenumbers' <= WORD,
            'Characteristics' <= DWORD,
        )

@cache
def IMAGE_IMPORT_DESCRIPTOR():
    return 'IMAGE_IMPORT_DESCRIPTOR' <= Struct(
        '_' <= Union(
            'Characteristics'    <= DWORD,
            'OriginalFirstThunk' <= DWORD
        ),
        'TimeDateStamp'  <= DWORD,
        'ForwarderChain' <= DWORD,
        'Name'           <= DWORD,
        'FirstThunk'     <= DWORD,
    )

@cache
def IMAGE_DEBUG_DIRECTORY():
    return 'IMAGE_DEBUG_DIRECTORY' <= Struct(
        'Characteristics' <= DWORD,
        'TimeDateStamp'   <= DWORD,
        'MajorVersion' <= WORD,
        'MinorVersion' <= WORD,
        'Type'             <= DWORD,
        'SizeOfData'       <= DWORD,
        'AddressOfRawData' <= DWORD,
        'PointerToRawData' <= DWORD,
    )

@cache
def IMAGE_SYMBOL():
    return 'IMAGE_SYMBOL' <= Struct(
        'N' <= Union(
            'ShortName' <= Array(8, BYTE),
            'Name' <= Struct(
                'Zero'   <= DWORD,
                'Offset' <= DWORD,
            ),
        ),
        'Value'              <= DWORD,
        'SectionNumber'      <= WORD,
        'Type'               <= WORD,
        'StorageClass'       <= BYTE,
        'NumberOfAuxSymbols' <= BYTE,
    )

@cache
def IMAGE_AUX_SYMBOL():
    return 'IMAG_AUX_SYMBOL' <= Union(
        'Sym' <= Struct(
            'TagIndex' <= DWORD,
            'Misc' <= Union(
                'LnSz' <= Struct(
                    'Linenumber' <= WORD,
                    'Size'       <= WORD,
                ),
                'TotalSize' <= DWORD,
            ),
            'FcnAry' <= Union(
                'Function' <= Struct(
                    'PointerToLinenumber'   <= DWORD,
                    'PointerToNextFunction' <= DWORD,
                ),
                'Array' <= Struct(
                    'Dimension' <= Array(4, WORD),
                ),
            ),
            'TvIndex' <= WORD
        ),
        'File' <= Struct(
            'Name' <= Array(18, u8),
        ),
        'Section' <= Struct(
            'Length'    <= DWORD,
            'NumberOfRelocations' <= WORD,
            'NumberOfLinenumbers' <= WORD,
            'CheckSum'  <= DWORD,
            'Number'    <= SHORT,
            'Selection' <= BYTE,
        )
    )

@cache
def IMAGE_COFF_STRING_TABLE_SIZE():
    return 'Size' <= DWORD

@cache
def IMAGE_THUNK_DATA(parser):
    if parser.bits == 32:
        return 'IMAGE_THUNK_DATA' <= Struct(
            'u1' <= Union(
                'ForwarderString' <= DWORD, # PBYTE
                'Function'        <= DWORD, # PDWORD
                'Ordinal'         <= DWORD,
                'AddressOfData'   <= DWORD, # PIMAGE_IMPORT_BY_NAME
            )
        )
    else:
        return 'IMAGE_THUNK_DATA' <= Struct(
            'u1' <= Union(
                'ForwarderString' <= ULONGLONG, # PBYTE
                'Function'        <= ULONGLONG, # PDWORD
                'Ordinal'         <= ULONGLONG,
                'AddressOfData'   <= ULONGLONG, # PIMAGE_IMPORT_BY_NAME
            )
        )

@cache
def IMAGE_IMPORT_BY_NAME():
    return 'IMAGE_IMPORT_BY_NAME' <= Struct(
        'Hint' <= WORD,
        'Name' <= VariableArray(lambda c,_: c!=0, BYTE)
    )
