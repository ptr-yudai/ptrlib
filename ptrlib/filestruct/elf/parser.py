"""This package provides a simple ELF parser.
"""
import functools
from logging import getLogger
from typing import Any, Generator, List, Optional
from ptrlib.types import PtrlibBitsT, PtrlibArchT
from ptrlib.filestruct.bunkai import \
    u8, u16, u32, u64, s32, s64, u8be, u16be, u32be, u64be, s32be, s64be
from .structs import *

logger = getLogger(__name__)
cache = functools.lru_cache


class ELFParser:
    """ELF file parser.
    """
    def __init__(self, filepath: str):
        """
        Args:
            filepath (str): The path to an ELF file to parse.
        """
        self.elfclass: PtrlibBitsT
        self.arch: PtrlibArchT

        self.stream = open(filepath, 'rb')
        if not self._identify():
            raise ValueError("Not a valid ELF file")

        # Set primitive types
        if self.little_endian:
            self.Elf_Byte = u8
            self.Elf_Half = u16
            self.Elf_Word = u32
            self.Elf_Word64 = u64
            self.Elf_Addr = u32 if self.elfclass == 32 else u64
            self.Elf_Offset = self.Elf_Addr
            self.Elf_Sword = s32
            self.Elf_Xword = u32 if self.elfclass == 32 else u64
            self.Elf_Sxword = s32 if self.elfclass == 32 else s64
        else:
            self.Elf_Byte = u8be
            self.Elf_Half = u16be
            self.Elf_Word = u32be
            self.Elf_Word64 = u64be
            self.Elf_Addr = u32be if self.elfclass == 32 else u64be
            self.Elf_Offset = self.Elf_Addr
            self.Elf_Sword = u32be
            self.Elf_Xword = u32be if self.elfclass == 32 else u64be
            self.Elf_Sxword = s32be if self.elfclass == 32 else s64be

        # Parse ELF header
        self.stream.seek(0)
        self.ehdr = Elf_Ehdr(self).parse_stream(self.stream)

        if self.ehdr['e_machine'] in ('EM_386', 'EM_X86_64'):
            self.arch = 'intel'
        elif self.ehdr['e_machine'] in ('EM_ARM', 'EM_AARCH64'):
            self.arch = 'arm'
        elif self.ehdr['e_machine'] == 'EM_SPARC':
            self.arch = 'sparc'
        elif self.ehdr['e_machine'] == 'EM_MIPS':
            self.arch = 'mips'
        elif self.ehdr['e_machine'] == 'EM_RISCV':
            self.arch = 'risc-v'
        else:
            self.arch = 'unknown'

    @cache
    def section_by_name(self, name: str) -> Any:
        """Look up a section by name

        Args:
            name (str): Section name.

        Returns:
            dict: A section.

        Raises:
            KeyError: Section is not found.
        """
        head = self.section_at(self.ehdr['e_shstrndx'])['sh_offset']

        for i in range(self.ehdr['e_shnum']):
            shdr = self.section_at(i)
            section_name = self.string_at(head + shdr['sh_name'])

            if section_name == name:
                return shdr

        raise KeyError(f"Section {name} is not found.")

    @cache
    def section_at(self, n: int) -> Any:
        """Get n-th section.

        Args:
            n (int): The index of the section to look up.

        Returns:
            dict: A section.
        """
        self.stream.seek(self.ehdr['e_shoff'] + n * self.ehdr['e_shentsize'])
        return Elf_Shdr(self).parse_stream(self.stream)

    @cache
    def segment_at(self, n: int) -> Any:
        """Get n-th segment.

        Args:
            n (int): The index of the segment to look up.

        Returns:
            dict: A segment.
        """
        self.stream.seek(self.ehdr['e_phoff'] + n * self.ehdr['e_phentsize'])
        return Elf_Phdr(self).parse_stream(self.stream)

    @cache
    def string_at(self, offset) -> Optional[bytes]:
        """Get a NULL-terminated string at an offset.

        Args:
            offset (int): An offset to a string.

        Returns:
            bytes: A parsed string, or None if the offset is invalid.
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

            chunks.append(chunk)
            if len(chunk) < 0x100:
                break

        return b''.join(chunks) if found else None

    def iter_sections(self) -> Generator[Any, None, None]:
        """Iterate over all sections.

        Yield:
            dict: A section.
        """
        for n in range(self.ehdr['e_shnum']):
            yield self.section_at(n)

    def iter_symtab(self, shdr) -> Generator[Any, None, None]:
        """Iterate over all symbols in symtab.

        Yield:
            dict: A symbol.
        """
        for j in range(1, shdr['sh_size'] // shdr['sh_entsize']):
            self.stream.seek(shdr['sh_offset'] + j * shdr['sh_entsize'])
            yield Elf_Sym(self).parse_stream(self.stream)

    def iter_rel(self) -> Generator[Any, None, None]:
        """Iterate over the relocation table.

        Yield:
            dict: A relocation entry.
        """
        for i in range(self.ehdr['e_shnum']):
            shdr = self.section_at(i)
            if shdr['sh_type'] != 'SHT_REL':
                if shdr['sh_type'] != 'SHT_RELA':
                    continue

            # Found relocation section
            for j in range(shdr['sh_size'] // shdr['sh_entsize']):
                rel_offset = shdr['sh_offset'] + j * shdr['sh_entsize']

                self.stream.seek(rel_offset)
                if shdr['sh_type'] == 'SHT_REL':
                    rel = Elf_Rel(self).parse_stream(self.stream)
                else:
                    rel = Elf_Rela(self).parse_stream(self.stream)

                yield shdr, rel

    @cache
    def segments(self, writable: Optional[bool]=None, executable: Optional[bool]=None) -> List[Any]:
        """Get segments of a specific permission.

        Args:
            writable (bool, optional): Filter only writable segments if true.
            executable (bool, optional): Filter only executable segments if true.

        Returns:
            list: A list of segments.
        """
        # TODO: Support writable/executable=False
        result = []
        for i in range(self.ehdr['e_phnum']):
            seghdr = self.segment_at(i)

            if writable is None and executable is None:
                result.append(seghdr)

            elif writable and executable is None:
                if seghdr['p_flags'] & ENUM_P_FLAGS['PF_W']:
                    result.append(seghdr)

            elif writable is None and executable:
                if seghdr['p_flags'] & ENUM_P_FLAGS['PF_X']:
                    result.append(seghdr)

            else:
                if seghdr['p_flags'] & ENUM_P_FLAGS['PF_W'] \
                   and seghdr['p_flags'] & ENUM_P_FLAGS['PF_X']:
                    result.append(seghdr)

        return result

    @cache
    def tag(self, key: str) -> Optional[Any]:
        """Get a tag by key.

        Args:
            key (str): A key string.

        Returns:
            dict: A tag, or None if there is not tag corresponding the given key.
        """
        for i in range(self.ehdr['e_shnum']):
            shdr = self.section_at(i)
            if shdr['sh_type'] != 'SHT_DYNAMIC':
                continue

            i = 0
            while True:
                self.stream.seek(shdr['sh_offset'] + i * Elf_Dyn(self).size)
                tag = Elf_Dyn(self).parse_stream(self.stream)
                if tag['d_tag'] == key:
                    return tag
                if tag['d_tag'] == 'DT_NULL':
                    break
                i += 1

        return None

    def symbol_name(self, symbols: Any, n: int) -> Optional[bytes]:
        """Get a symbol name.

        Args:
            symbols (list): A symbol table.
            n (int): The index of the symbol.

        Returns:
            bytes: A symbol name, or None if the parameters are invalid.
        """
        strtab = self.section_at(symbols['sh_link'])
        self.stream.seek(symbols['sh_offset'] + n * symbols['sh_entsize'])
        symtab = Elf_Sym(self).parse_stream(self.stream)
        return self.string_at(strtab['sh_offset'] + symtab['st_name'])

    def _identify(self):
        """Check the endian and class of the ELF.
        """
        self.stream.seek(0)
        magic = self.stream.read(4)
        if magic != b'\x7fELF':
            logger.warning("Invalid ELF header")
            return False

        ei_class = self.stream.read(1)
        if ei_class == b'\x01':
            self.elfclass = 32
        elif ei_class == b'\x02':
            self.elfclass = 64
        else:
            logger.warning("Invalid EI_CLASS. Assuming 64-bit ELF...")
            self.elfclass = 64

        ei_data = self.stream.read(1)
        if ei_data == b'\x01':
            self.little_endian = True
        elif ei_data == b'\x02':
            self.little_endian = False
        else:
            logger.warning("Invalid EI_DATA. Assuming little endian...")
            self.little_endian = True

        return True

    def __del__(self):
        self.stream.close()


__all__ = ['ELFParser']
