"""This package provides a simple ELF file analyzer.
"""
import functools
import os
from logging import getLogger
from typing import Dict, Generator, Optional, Tuple, Union as TypingUnion
from zlib import crc32
from ptrlib.annotation import PtrlibArchT, PtrlibBitsT, PtrlibAssemblySyntaxT
from ptrlib.binary.packing import u32
from ptrlib.binary.encoding import str2bytes
from ptrlib.pwn.xop import Gadget
from .parser import ELFParser

logger = getLogger(__name__)
cache = functools.lru_cache


class ELF:
    """ELF file analyzer.
    """
    def __init__(self, filepath: str):
        """
        Args:
            filepath (str): The path to an ELF file to parser.
        """
        self.filepath = os.path.realpath(filepath)
        self._parser = ELFParser(self.filepath)
        self._base = 0
        self._debug_parser = self._get_debug_parser()
        self._gadget = Gadget(self)

    @property
    def bits(self) -> PtrlibBitsT:
        """The bits of this ELF.

        Returns either 32 or 64.
        """
        return self._parser.elfclass

    @property
    def arch(self) -> PtrlibArchT:
        """The architecture name of this ELF.

        Return one of the following values:
            - `"intel"`: Intel and AMD series (`EM_386`, `EM_X86_64`)
            - `"arm"`: ARM series (`EM_ARM`, `EM_AARCH64`)
            - `"mips"`: MIPS series (`EM_MIPS`)
            - `"sparc"`: SPARC series (`EM_SPARC`)
            - `"risc-v"`: RISC-V series (`EM_RISCV`)
        """
        return self._parser.arch

    def _get_debug_parser(self):
        # ref: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html
        dirname = os.path.dirname(self.filepath)

        debug_info_paths = []
        def add(*args: str, crc: Optional[int]=None):
            debug_info_paths.append((os.path.realpath(os.path.join(*args)), crc))

        if self.build_id is not None:
            build_id_hex = self.build_id.hex()
            add(f"/usr/lib/debug/.build-id/{build_id_hex[:2]}/{build_id_hex[2:]}.debug")
            add(dirname, f".debug/.build-id/{build_id_hex[:2]}/{build_id_hex[2:]}.debug")

        if self._debuglink_info is not None:
            name, crc = self._debuglink_info
            try:
                decoded_name = name.decode()
                add(dirname, decoded_name, crc=crc)
                add(dirname, ".debug", decoded_name, crc=crc)
                add("/usr/lib/debug", dirname, decoded_name, crc=crc)
            except UnicodeDecodeError:
                pass

        for path, crc in debug_info_paths:
            if not os.access(path, os.R_OK):
                continue

            if crc is not None:
                with open(path, "rb") as f:
                    content = f.read()
                    if crc32(content) != crc:
                        continue
            logger.info("Debug file loaded from %s", path)
            return ELFParser(path)

        return None

    @property
    @cache
    def build_id(self) -> Optional[bytes]:
        """Get the build-id of this ELF file.

        returns:
            bytes: The build-id, or None if there is no build-id section.
        """
        shdr = self._offset_section(b'.note.gnu.build-id')
        if shdr is None:
            return None

        self._parser.stream.seek(shdr - self._load_address)
        n_namesz = u32(self._parser.stream.read(4))
        n_descsz = u32(self._parser.stream.read(4))
        self._parser.stream.read(4)
        self._parser.stream.read(n_namesz)
        build_id = self._parser.stream.read(n_descsz)
        return build_id

    @property
    @cache
    def _debuglink_info(self) -> Optional[Tuple[bytes, int]]:
        shdr = self._parser.section_by_name(b'.gnu_debuglink')
        if shdr is None:
            return None

        self._parser.stream.seek(shdr['sh_offset'] - self._load_address)
        _debugfile_name = b""
        while True:
            c = self._parser.stream.read1(1)
            if c in (b'', b'\x00'):
                break
            _debugfile_name += c

        # Seek to align
        self._parser.stream.read(-(len(_debugfile_name) + 1) % 4)
        crc = u32(self._parser.stream.read(4))

        return _debugfile_name, crc

    @property
    def base(self) -> int:
        """The load address of this ELF.

        This property holds:
            - 0 by default, or the base address set by user if PIE is enabled
            - The load address by default, or the base set by user if PIE is disabled

        Returns:
            int: The address where the ELF is loaded.
        """
        return self._base

    @base.setter
    def base(self, base: int):
        """Set the load address of this ELF.

        Args:
            int: The base address.

        Examples:
            ```
            elf = ELF("./chall")
            elf.base = 0x555555554000
            libc = ELF("./libc.so.6")
            libc.base = u64(leak) - libc.main_arena() - 0x60
            ```
        """
        # Support integer-like types such as mpz int
        base = int(base)

        logger.info("New base address: 0x%x", base)
        if base & 0xfff != 0:
            logger.error(" *****************************************\n" \
                         " * The base address does not look valid! *\n" \
                         " *****************************************")

        self._base = base

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
        """Get the virtual address of PT_LOAD segment.
        """
        for i in range(self._parser.ehdr['e_phnum']):
            seghdr = self._parser.segment_at(i)
            if seghdr['p_type'] == 'PT_LOAD':
                return seghdr['p_vaddr']
        return 0

    def symbol(self, name: TypingUnion[str, bytes]) -> Optional[int]:
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
        return self._pie_add_base + offset

    @cache
    def _offset_symbol(self, name: TypingUnion[str, bytes]) -> Optional[int]:
        if isinstance(name, str):
            name = str2bytes(name)

        # Find symbol
        for parser in [self._parser, self._debug_parser]:
            if parser is None:
                continue

            for shdr in parser.iter_sections():
                if shdr['sh_type'] not in ["SHT_SYMTAB", "SHT_DYNSYM", "SHT_SUNW_LDYNSYM"]:
                    continue

                strtab = parser.section_at(shdr['sh_link'])
                for symtab in parser.iter_symtab(shdr):
                    sym_name = parser.string_at(
                        strtab['sh_offset'] + symtab['st_name']
                    )
                    if sym_name == b'':
                        continue

                    if sym_name == name:
                        # TODO: Support searching for multiple identical symbols
                        return symtab['st_value']

        return None

    def symbols(self) -> Dict[bytes, int]:
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

    def search(self,
               pattern: TypingUnion[str, bytes],
               writable: Optional[bool]=None,
               executable: Optional[bool]=None) -> Generator[int, None, None]:
        """Find binary data from the ELF.

        Args:
            pattern (bytes): Data to find.

        Returns:
            generator: The address of the found data.
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

    def find(self,
             pattern: TypingUnion[str, bytes],
             writable: Optional[bool]=None,
             executable: Optional[bool]=None) -> Generator[int, None, None]:
        """Alias of ```search```
        """
        yield from self.search(pattern, writable, executable)

    def addr2offset(self, addr: int) -> Optional[int]:
        """Returns the offset in the ELF corresponding to a given virtual address.

        Args:
            addr (int): Virtual address.
        
        Returns:
            int | None: Offset. If a non-existent address is specified, None is returned
        """
        parser = self._parser

        # serach the segment
        for segment in parser.segments():
            if segment["p_type"] == "PT_LOAD":
                start_vaddr = segment["p_vaddr"]
                end_vaddr = start_vaddr + segment["p_memsz"]

                if start_vaddr <= addr < end_vaddr:
                    segment_offset = segment["p_offset"]
                    offset_from_segment_base = addr - start_vaddr
                    offset = segment_offset + offset_from_segment_base

                    return offset

        return None

    def read(self, addr: int, size: int) -> Optional[bytes]:
        """Returns the bytes of a size from a virtual address.

        If a non-existent address is specified, None is returned.

        Unintended behaviour will occur if the segment is crossed.

        Args:
            addr (int): Start virtual address
            size (int): Size of bytes

        Returns:
            bytes: Bytes in the file. 
                   If a non-existent address is specified, None is returned
        """
        parser = self._parser

        offset = self.addr2offset(addr)

        if offset is not None:
            stream = parser.stream
            # save position
            current_offset = stream.tell()

            # get bytes
            stream.seek(offset)
            ret = stream.read(size)

            # recover position
            stream.seek(current_offset)

            return ret

        return None

    def plt(self, name: TypingUnion[str, bytes]) -> Optional[int]:
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
    def _offset_plt(self, name: TypingUnion[str, bytes]) -> Optional[int]:
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

        got = self.section('.got')
        assert got is not None, "'.got' section not found"
        base_got = got - self._load_address

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

    def got(self, name: TypingUnion[str, bytes]) -> Optional[int]:
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
        return self._pie_add_base + offset

    @cache
    def _offset_got(self, name: TypingUnion[str, bytes]) -> Optional[int]:
        if isinstance(name, str):
            name = str2bytes(name)

        for (shdr, rel) in self._parser.iter_rel():
            if self._parser.elfclass == 32:
                sym_idx = rel['r_info'] >> 8
            else:
                sym_idx = rel['r_info'] >> 32
            if sym_idx == 0:
                continue

            symbols = self._parser.section_at(shdr['sh_link'])
            symbol_name = self._parser.symbol_name(symbols, sym_idx)
            if symbol_name == name:
                return rel['r_offset']

        return None

    def main_arena(self, use_symbol: bool=True) -> Optional[int]:
        """Find main_arena offset

        Args:
            use_symbol (bool) Try to search for symbol first

        Returns:
            int: Offset to main_arena (returns None if it's not libc)
        """
        offset = self._offset_main_arena(use_symbol)
        if offset is None:
            logger.warning('`main_arena` only works for libc binary.')
            return None
        else:
            return self._pie_add_base + offset

    @cache
    def _offset_main_arena(self, use_symbol: bool=True) -> Optional[int]:
        if use_symbol:
            ofs_arena = self._offset_symbol('main_arena')
            if ofs_arena is not None:
                return ofs_arena

        # NOTE: This is a heuristic function
        ofs_stdin = self._offset_symbol('_IO_2_1_stdin_')
        ofs_realloc_hook = self._offset_symbol('__realloc_hook')
        ofs_malloc_hook = self._offset_symbol('__malloc_hook')
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
            ofs_tzname = self._offset_symbol('tzname')
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
    def _offset_section(self, name: TypingUnion[str, bytes]) -> Optional[int]:
        if isinstance(name, str):
            name = str2bytes(name)

        shdr = self._parser.section_by_name(name)
        if shdr:
            return shdr['sh_addr']
        else:
            return None

    def gadget(self, code: TypingUnion[str, bytes], syntax: PtrlibAssemblySyntaxT='intel'):
        """Find ROP/COP gadgets.

        Args:
            code (str/bytes): Assembly or machine code of ROP gadget
            syntax (str): Syntax of code (default to intel)

        Returns:
            generator: Generator to yield the addresses of the found gadgets
        """
        return self._gadget.search(code, syntax)

    @cache
    def relro(self) -> int:
        """Check RELRO.

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
        if flags and flags['d_un'] & 0x8:
            return 2
        if flags_1 and flags_1['d_un'] & 0x8:
            return 2
        return 1

    @cache
    def nx(self) -> bool:
        """Check NX bit.

        Check if NX bit is enabled.

        Returns:
            bool: True if NX is enabled, otherwise False.
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
        """Check SSP.
        
        Check if the binary is protected with canary.
        This function is heuristic and just checks if some symbols such as `__stack_chk_fail` exist.

        Returns:
            bool: True if enabled, otherwise False.
        """
        if self.got('__stack_chk_fail') is not None \
           or self.got('__stack_smash_handler') is not None \
           or self.symbol('__stack_chk_fail') is not None \
           or self.symbol('__stack_smash_handler') is not None:
            return True
        return False

    @cache
    def pie(self) -> bool:
        """Check PIE.

        Check if PIE is enabled or disabled.

        Returns:
            bool: True if enabled, otherwise False.
        """
        if self._parser.tag('EXEC'):
            return False

        if self._parser.ehdr['e_type'] == 'ET_DYN':
            if self._parser.tag('DT_DEBUG'):
                return True
            return True # What's this?
        return False


__all__ = ['ELF']
