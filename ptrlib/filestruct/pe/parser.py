import functools
from logging import getLogger
from .enums import *
from .structs import *

logger = getLogger(__name__)

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

        # Identify PE spec
        self.stream.seek(
            self.doshdr['e_lfanew'] + DWORD.size + IMAGE_FILE_HEADER().size
        )
        magic = IMAGE_OPTIONAL_HEADER_MAGIC().parse_stream(self.stream)
        if magic == 0x20b: # PE+
            self.bits = 64
        elif magic == 0x10b or magic == 0x107: # PE32 or ROM
            self.bits = 32
        else:
            logger.error("Invalid Magic in IMAGE_NT_HEADER.OptionalHeader")

        # Parse IMAGE_NT_HEADER
        self.stream.seek(self.doshdr['e_lfanew'])
        self.nthdr = IMAGE_NT_HEADER(self).parse_stream(self.stream)

        # Parse section tables
        self.sections = [
            IMAGE_SECTION_HEADER(self).parse_stream(self.stream)
            for _ in range(self.nthdr['FileHeader']['NumberOfSections'])
        ]
        for i in range(self.nthdr['FileHeader']['NumberOfSections']):
            self.sections[i]['Name'] = ''.join(
                map(chr, self.sections[i]['Name'])
            ).rstrip('\0')

        # Parse tables
        self._parse_coff()
        self._parse_export_directory()
        self._parse_import_directory()

    @cache
    def rva_to_section(self, rva):
        """Find section corresponding to a specific RVA

        Args:
            rva (int): RVA address

        Returns:
            dict: IMAGE_SECTION_HEADER if found, otherwise None
        """
        for section in self.sections:
            if section['VirtualAddress'] <= rva and \
               rva < section['VirtualAddress'] + section['SizeOfRawData']:
                return section

        logger.warning(f"Invalid RVA: 0x{rva:x}")
        return None

    @cache
    def rva_to_offset(self, rva):
        """Convert RVA to file offset

        Args:
            rva (int): RVA address

        Returns:
            int: Offset in file (-1 if invalid)
        """
        section = self.rva_to_section(rva)
        if section is None:
            return None

        return rva - section['VirtualAddress'] + section['PointerToRawData']

    @cache
    def string_at(self, offset):
        """Get C-string at specific file offset
        """
        self.stream.seek(offset)
        chunks = []
        found = False
        while True:
            chunk = self.stream.read(0x100)
            ei = chunk.find(b'\x00')
            if ei >= 0:
                chunks.append(chunk[:ei])
                found = True
                break
            else:
                chunks.append(chunk)
            if len(chunk) < 0x100:
                break
        return b''.join(chunks) if found else None

    def _parse_coff(self):
        """Parse COFF symbol table and string table
        """
        self._symbol_table = []
        self._offset_string_table = -1
        self._size_string_table = -1

        offset = self.nthdr['FileHeader']['PointerToSymbolTable']
        if offset == 0:
            return

        # Parse symbol table
        self.stream.seek(offset)
        naux = 0
        for _ in range(self.nthdr['FileHeader']['NumberOfSymbols']):
            if naux == 0:
                image_symbol = IMAGE_SYMBOL().parse_stream(self.stream)
                naux = image_symbol['NumberOfAuxSymbols']
                image_aux_symbols = []

            else:
                naux -= 1
                image_aux_symbol = IMAGE_AUX_SYMBOL().parse_stream(self.stream)
                image_aux_symbols.append(image_aux_symbol)

            if naux == 0:
                self._symbol_table.append((image_symbol, image_aux_symbols))

        # Parse string table
        size = IMAGE_COFF_STRING_TABLE_SIZE().parse_stream(self.stream)
        self._offset_string_table = self.stream.tell() \
            - IMAGE_COFF_STRING_TABLE_SIZE().size
        self._size_string_table = size

        # Resolve symbol name
        for image_symbol, _ in self._symbol_table:
            self._resolve_symbol_name(image_symbol)

    def _parse_export_directory(self):
        """
        """
        pass

    def _parse_import_directory(self):
        """
        """
        i = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        dd = self.nthdr['OptionalHeader']['DataDirectories'][i]
        if dd['VirtualAddress'] == 0 and dd['Size'] == 0:
            return

        offset = self.rva_to_offset(dd['VirtualAddress'])
        if offset is None:
            logger.error("Failed to parse import directory (Invalid RVA)")
            return

        # Parse IMAGE_IMPORT_DESCRIPTOR
        self._import_table = []
        self.stream.seek(offset)
        while True:
            table = IMAGE_IMPORT_DESCRIPTOR().parse_stream(self.stream)
            if table['Name'] == 0 and table['FirstThunk'] == 0:
                break
            self._import_table.append(table)

        # Resolve names
        for table in self._import_table:
            self._resolve_imports(table)

    def _resolve_symbol_name(self, image_symbol):
        """Resolve names in a symbol table
        """
        if image_symbol['N']['Name']['Zero'] == 0:
            offset = image_symbol['N']['Name']['Offset']
            if offset >= self._size_string_table:
                name = None
            else:
                name = self.string_at(self._offset_string_table + offset)
        else:
            name = b''.join(
                map(lambda c: bytes([c]), image_symbol['N']['ShortName'])
            ).rstrip(b'\0')

        image_symbol['Name'] = name

    def _resolve_imports(self, import_table):
        """Resolve names in an import table
        """
        # Resolve DLL name
        offset = self.rva_to_offset(import_table['Name'])
        import_table['Name'] = self.string_at(offset)

    def iter_iat(self, import_table):
        """Iterate over IAT corresponding to an import table
        """
        oft = import_table['_']['OriginalFirstThunk']
        ft = import_table['FirstThunk']
        p_thunk_name = self.rva_to_offset(oft)
        p_thunk_func = self.rva_to_offset(ft)

        while True:
            # Parse thunk name and function
            self.stream.seek(p_thunk_name)
            thunk_name = IMAGE_THUNK_DATA(self).parse_stream(self.stream)
            self.stream.seek(p_thunk_func)
            thunk_func = IMAGE_THUNK_DATA(self).parse_stream(self.stream)
            if thunk_func['u1']['Function'] == 0:
                break

            # Get function name
            offset = self.rva_to_offset(thunk_name['u1']['AddressOfData'])
            self.stream.seek(offset)
            ibn = IMAGE_IMPORT_BY_NAME().parse_stream(self.stream)
            name = ''.join(map(chr, ibn['Name']))

            yield thunk_func['u1']['Function'], name

            p_thunk_name += IMAGE_THUNK_DATA(self).size
            p_thunk_func += IMAGE_THUNK_DATA(self).size

    def iter_imports(self):
        """Iterate over import table
        """
        for table in self._import_table:
            yield table

    def iter_symbol_table(self):
        """Iterate over symbol table
        """
        for image_symbol, image_aux_symbol in self._symbol_table:
            yield (image_symbol, image_aux_symbol)

    def iter_sections(self):
        """Iterate over sections
        """
        for section in self.sections:
            yield section
