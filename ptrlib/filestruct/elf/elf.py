import functools
import os
from logging import getLogger
from typing import Dict, Generator, Optional
from ptrlib.binary.packing import *
from ptrlib.arch.common import assemble
from ptrlib.binary.encoding import str2bytes, bytes2str
from .parser import ELFParser

logger = getLogger(__name__)

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


class ELF(object):
    def __init__(self, filepath):
        """ELF Parser
        """
        self.filepath = os.path.realpath(filepath)
        self._parser = ELFParser(self.filepath)
        self._base = 0

    @property
    def base(self) -> int:
        """Get the load address
        This property has
        - 0 by default, or the base set by user if PIE is enabled
        - Load address by default, or the base set by user if PIE is disabled

        Returns:
            int: The address where the ELF is loaded
        """
        return self._base

    @base.setter
    def base(self, base: int):
        """Set the load address

        Args:
            int: The base address to be used
        """
        # Support integer-like types such as mpz int
        base = int(base)

        logger.info("New base address: 0x{:x}".format(base))
        if base & 0xfff != 0:
            logger.error("The address doesn't look valid.")

        self._base = base

    def set_base(self, base):
        logger.error("Deprecated: This feature will be removed in the future. "
                     "Use `elf.base = ...` instead.")
        self.base = base

    @property
    def _pie_add_base(self) -> int:
        """Get the load address
        This property has
        - 0 by default, or the base set by user if PIE is enabled
        - Always 0 if PIE is disabled
        """
        if self.pie():
            return self.base
        else:
            return 0

    @property
    @cache
    def _load_address(self) -> int:
        for i in range(self._parser.ehdr['e_phnum']):
            seghdr = self._parser.segment_at(i)
            if seghdr['p_type'] == 'PT_LOAD':
                return seghdr['p_vaddr']
        else:
            return 0

    def symbol(self, name: Union[str, bytes]) -> Optional[int]:
        """Get the address of a symbol

        Find the address corresponding to a given symbol.

        Args:
            name (str): The symbol name to find

        Returns:
            int: The address of the symbol
        """
        offset = self._offset_symbol(name)
        if offset is None:
            return None
        else:
            return self._pie_add_base + offset

    @cache
    def _offset_symbol(self, name: Union[str, bytes]) -> Optional[int]:
        if isinstance(name, str):
            name = str2bytes(name)

        # Find symbol
        for shdr in self._parser.iter_sections():
            if shdr['sh_type'] not in ["SHT_SYMTAB", "SHT_DYNSYM", "SHT_SUNW_LDYNSYM"]:
                continue

            strtab = self._parser.section_at(shdr['sh_link'])
            for symtab in self._parser.iter_symtab(shdr):
                sym_name = self._parser.string_at(
                    strtab['sh_offset'] + symtab['st_name']
                )
                if sym_name == b'':
                    continue

                if sym_name == name:
                    return symtab['st_value']

        return None

    def symbols(self) -> Dict[str, int]:
        """Get all symbols

        Find all symbols and their addresses.

        Returns:
            dict: A dictionary containing the symbol name in key and address in value.
        """
        return self._offset_symbols(self._pie_add_base)

    @cache
    def _offset_symbols(self, base=0) -> Dict[bytes, int]:
        symbols = {}
        for shdr in self._parser.iter_sections():
            if shdr['sh_type'] not in ["SHT_SYMTAB", "SHT_DYNSYM", "SHT_SUNW_LDYNSYM"]:
                continue

            strtab = self._parser.section_at(shdr['sh_link'])
            for symtab in self._parser.iter_symtab(shdr):
                sym_name = self._parser.string_at(
                    strtab['sh_offset'] + symtab['st_name']
                )
                if sym_name == b'':
                    continue

                symbols[sym_name] = base + symtab['st_value']

        return symbols

    def search(self, pattern: Union[str, bytes], writable: Optional[bool]=None, executable: Optional[bool]=None) -> Generator[int, None, None]:
        """Find binary data from the ELF

        Args:
            pattern (bytes): Data to find

        Returns:
            generator: Address
        """
        if isinstance(pattern, str):
            pattern = str2bytes(pattern)

        segments = self._parser.segments(writable, executable)
        for seghdr in segments:
            addr   = seghdr['p_vaddr']
            memsz  = seghdr['p_memsz']
            zeroed = memsz - seghdr['p_filesz']
            offset = seghdr['p_offset']

            self._parser.stream.seek(offset)
            data = self._parser.stream.read(memsz)
            data += b'\x00' * zeroed

            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break

                yield self._pie_add_base + addr + offset
                offset += 1

    def find(self, pattern: Union[str, bytes], writable: Optional[bool]=None, executable: Optional[bool]=None) -> Generator[int, None, None]:
        """Alias of ```search```
        """
        for result in self.search(pattern, writable, executable):
            yield result

    def plt(self, name: Union[str, bytes]) -> Optional[int]:
        """Get a PLT address
        Lookup the PLT table and find the corresponding address

        Args:
            name (str): The function name to find

        Returns:
            int: The address of the PLT section
        """
        offset = self._offset_plt(name)
        if offset is None:
            return None
        else:
            return self._pie_add_base + offset

    @cache
    def _offset_plt(self, name: Union[str, bytes]) -> Optional[int]:
        if isinstance(name, str):
            name = str2bytes(name)

        target_got = self._offset_got(name)
        if target_got is None:
            return None

        for section_name in (b".plt", b".plt.got", b".plt.sec"):
            shdr = self._parser.section_by_name(section_name)
            if shdr is None:
                continue

            self._parser.stream.seek(shdr['sh_addr'] - self._load_address)
            code = self._parser.stream.read(shdr['sh_size'])
            xref = self._plt_ref_list(code, shdr)

            if target_got in xref:
                return xref[target_got]

        return None

    def _plt_ref_list(self, code, shdr):
        xref = {}
        i = 0
        base_got = self.section('.got') - self._load_address

        # TODO: Support more architecture
        while i < shdr['sh_size'] - 6:
            if self._parser.elfclass == 32:
                # 32-bit
                if code[i:i+2] == b'\xff\x25':
                    # jmp DWORD PTR ds:imm
                    addr_got = u32(code[i+2:i+6])
                    xref[addr_got] = shdr['sh_addr'] + i
                    i += 6
                elif code[i:i+2] == b'\xff\xa3':
                    # jmp DWORD PTR [ebx+imm]
                    addr_got = base_got + u32(code[i+2:i+6])
                    xref[addr_got] = shdr['sh_addr'] + i
                    i += 6
                else:
                    i += 1

            else:
                # 64-bit
                if code[i:i+2] == b'\xff\x25':
                    # jmp QWORD PTR [rip+imm]
                    addr_got = shdr['sh_addr'] + i + 6 + u32(code[i+2:i+6])
                    if i > 4 and code[i-5:i] == b'\xf3\x0f\x1e\xfa\xf2':
                        # endbr64; bnd jmp ...
                        xref[addr_got] = shdr['sh_addr'] + i - 5
                    else:
                        xref[addr_got] = shdr['sh_addr'] + i
                    i += 6
                else:
                    i += 1

        return xref

    def got(self, name: Union[str, bytes]) -> Optional[int]:
        """Get a GOT address
        Lookup the GOT table and find the corresponding address

        Args:
            name (str): The function name to find

        Returns:
            int: The address of the GOT
        """
        offset = self._offset_got(name)
        if offset is None:
            return None
        else:
            return self._pie_add_base + offset

    @cache
    def _offset_got(self, name: Union[str, bytes]) -> Optional[int]:
        if isinstance(name, str):
            name = str2bytes(name)

        for (shdr, rel) in self._parser.iter_rel():
            if self._parser.elfclass == 32:
                sym_idx = rel['r_info'] >> 8
            else:
                sym_idx = rel['r_info'] >> 32
            if sym_idx == 0: continue

            symbols = self._parser.section_at(shdr['sh_link'])
            symbol_name = self._parser.symbol_name(symbols, sym_idx)
            if symbol_name == name:
                return rel['r_offset']

        return None

    def main_arena(self) -> Optional[int]:
        """Find main_arena offset

        Returns:
            int: Offset to main_arena (returns None if it's not libc)
        """
        offset = self._offset_main_arena()
        if offset is None:
            logger.warning('`main_arena` only works for libc binary.')
            return None
        else:
            return self._pie_add_base + offset

    @cache
    def _offset_main_arena(self) -> Optional[int]:
        # NOTE: This is a heuristic function
        ofs_stdin = self.symbol('_IO_2_1_stdin_')
        ofs_realloc_hook = self.symbol('__realloc_hook')
        ofs_malloc_hook = self.symbol('__malloc_hook')
        if ofs_realloc_hook is None \
           or ofs_malloc_hook is None \
           or ofs_stdin is None:
            return None

        if 0 < ofs_malloc_hook - ofs_stdin < 0x1000:
            # libc-2.33 or older
            if self._parser.elfclass == 32:
                return ofs_malloc_hook + 0x18
            else:
                return ofs_malloc_hook + (ofs_malloc_hook - ofs_realloc_hook)*2

        else:
            # libc-2.34 removed hooks
            ofs_tzname = self.symbol('tzname')
            if ofs_tzname is None: return None
            if self._parser.elfclass == 32:
                return ofs_tzname - 0x460
            else:
                return ofs_tzname - 0x8a0

    def section(self, name: str) -> Optional[int]:
        """Get a section by name

        Lookup and find a section by name and return the address.

        Args:
            name (str): The section name to find

        Returns:
            int: The address of the section
        """
        offset = self._offset_section(name)
        if offset is None:
            return None
        else:
            return self._pie_add_base + offset

    @cache
    def _offset_section(self, name: Union[str, bytes]) -> Optional[int]:
        if isinstance(name, str):
            name = str2bytes(name)

        shdr = self._parser.section_by_name(name)
        if shdr:
            return shdr['sh_addr']
        else:
            return None

    def gadget(self, code: Union[str, bytes], arch: Optional[str]=None, bits: Optional[int]=None, syntax: str='intel'):
        """Find ROP/COP gadget
        Args:
            code (str/bytes): Assembly or machine code of ROP gadget
            syntax (str): Syntax of code (default to intel)

        Returns:
            generator: Generator to yield the addresses of the found gadgets
        """
        if isinstance(code, bytes):
            code = bytes2str(code)

        # Determine architecture
        if arch is None:
            if self._parser.ehdr['e_machine'] == 'EM_386':
                arch = 'x86'
            elif self._parser.ehdr['e_machine'] == 'EM_X86_64':
                arch = 'amd64'
            elif self._parser.ehdr['e_machine'] == 'EM_ARM':
                arch = 'arm'
            elif self._parser.ehdr['e_machine'] == 'EM_AARCH64':
                arch = 'aarch64'
            else:
                raise NotImplementedError(
                    "The current architecture (e_machine={})".format(
                        self._parser.ehdr['e_machine']
                    ) + \
                    " is not supported by assembler."
                )

        if bits is None:
            bits = self._parser.elfclass

        # Assemble gadget
        code = assemble(code, bits=bits, arch=arch, syntax=syntax)
        return self.search(code, executable=True)

    @cache
    def relro(self) -> int:
        """Check RELRO
        Check if RELRO is full/partial enabled or disabled.

        Returns:
            int: 0 if disabled, 1 if partial enabled, and 2 if fully enabled.
        """
        for i in range(self._parser.ehdr['e_phnum']):
            seghdr = self._parser.segment_at(i)
            if seghdr['p_type'] == 'PT_GNU_RELRO':
                break
        else:
            return 0 # No relro

        flags = self._parser.tag('DT_FLAGS')
        flags_1 = self._parser.tag('DT_FLAGS_1')
        if self._parser.tag('DT_BIND_NOW'):
            return 2
        elif flags and flags['d_un'] & 0x8:
            return 2
        elif flags_1 and flags_1['d_un'] & 0x8:
            return 2
        else:
            return 1

    @cache
    def nx(self) -> bool:
        """Check NX bit
        Check if NX bit is enabled.

        Returns:
            bool: True if NX is enabled
        """
        for i in range(self._parser.ehdr['e_phnum']):
            seghdr = self._parser.segment_at(i)
            if seghdr['p_type'] == 'PT_GNU_STACK':
                if seghdr['p_flags'] & 1: # Stack is executable
                    return False
                return True
        return False

    @cache
    def ssp(self) -> bool:
        """Check SSP
        Check if the binary is protected with canary.

        Returns:
            bool: True if enabled, otherwise False.
        """
        if self.got('__stack_chk_fail') is not None \
           or self.got('__stack_smash_handler') is not None \
           or self.symbol('__stack_chk_fail') is not None \
           or self.symbol('__stack_smash_handler') is not None:
            return True
        else:
            return False

    @cache
    def pie(self) -> bool:
        """Check PIE
        Check if PIE is enabled or disabled.

        Returns:
            bool: True if enabled, otherwise False.
        """
        if self._parser.tag('EXEC'):
            return False

        if self._parser.ehdr['e_type'] == 'ET_DYN':
            if self._parser.tag('DT_DEBUG'):
                return True
            else:
                return True # What's this?
        return False
