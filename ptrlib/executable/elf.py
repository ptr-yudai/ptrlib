from ptrlib.console.color import Color
from ptrlib.util.encoding import *
from ptrlib.util.packing import *
from ptrlib.executable.elfstruct import *
from ptrlib.asm.assembler import *
from logging import getLogger
import re

logger = getLogger(__name__)

class ELF(object):
    def __init__(self, filepath):
        """ELF Parser
        """
        self.filepath = filepath
        self.stream = open(filepath, 'rb')
        if not self._identify():
            return

        # Register ELF structs
        self.structs = ELFStructs(self.little_endian, self.elfclass)
        self.structs.create_basic_structs()
        self.header = self._parse(self.structs.Elf_Ehdr, stream_pos=0)
        self.structs.create_advanced_structs(
            self.header.e_type,
            self.header.e_machine,
            self.header.e_ident.EI_OSABI
        )

        # String table section
        self.section_string = self._get_section(self.header.e_shstrndx)

        self.set_base()

    def symbol(self, name):
        """Get the address of a symbol

        Find the address corresponding to a given symbol.

        Args:
            name (str): The symbol name to find

        Return:
            int: The address of the symbol
        """
        if isinstance(name, str):
            name = str2bytes(name)

        # Find symbol
        for i in range(self.header.e_shnum):
            section_header = self._get_section(i)
            if section_header.sh_type not in ["SHT_SYMTAB", "SHT_DYNSYM", "SHT_SUNW_LDYNSYM"]:
                continue

            section_strtab = self._get_section(section_header.sh_link)
            for j in range(1, section_header.sh_size // section_header.sh_entsize):
                sym = self._parse(
                    self.structs.Elf_Sym,
                    stream_pos = section_header.sh_offset + j * section_header.sh_entsize
                )
                sym_name = self._get_string(section_strtab.sh_offset + sym.st_name)
                if sym_name == b'':
                    continue
                if sym_name == name:
                    return sym.st_value + (self.base() if self.pie() else 0)
        return None

    def find(self, pattern, stream_pos=0):
        """Alias of ```search```
        """
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

        self.stream.seek(stream_pos)
        data = self.stream.read()
        length = len(data)
        addr, index = 0, 0
        while addr < length:
            data = data[index:]
            if pattern in data:
                index = data.index(pattern)
                addr += index
                yield self.base() + addr
                addr, index = addr + 1, index + 1
            else:
                break

    def section(self, name):
        """Get a section by name

        Lookup and find a section by name and return the address.

        Args:
            name (str): The section name to find

        Return:
            int: The address of the section
        """
        if isinstance(name, str):
            name = str2bytes(name)

        section_header = self._get_section_by_name(name)
        if section_header:
            return section_header.sh_addr + (self.base() if self.pie() else 0)
        
        return None

    def set_base(self, base=None):
        """Set the load address

        Args:
            int: The base address to be used
        """
        self._base = base

    def base(self):
        """Get the load address

        Returns:
            int: The address where the ELF is loaded
        """
        if self._base is None:
            self._base = self._real_base()
        return self._base

    def _real_base(self):
        for i in range(self.header.e_phnum):
            segment_header = self._get_segment(i)
            if segment_header.p_type == "PT_LOAD":
                break
        else:
            return 0

        return segment_header.p_vaddr

    def plt(self, name):
        """Get a PLT address

        Lookup the PLT table and find the corresponding address

        Args:
            name (str): The function name to find

        Return:
            int: The address of the PLT section
        """
        if isinstance(name, str):
            name = str2bytes(name)

        if self.pie():
            target_got = self.got(name) - self.base()
        else:
            target_got = self.got(name)
        if target_got is None:
            return None

        for section_name in (b".plt", b".plt.got", b".plt.sec"):
            section_header = self._get_section_by_name(section_name)
            if section_header is None:
                continue

            self.stream.seek(section_header.sh_addr - self._real_base())
            code = self.stream.read(section_header.sh_size)
            xref = self._plt_ref_list(code, section_header)

            if target_got in xref:
                return xref[target_got] + (self.base() if self.pie() else 0)

        return self.section(".plt")

    def _plt_ref_list(self, code, sh):
        xref = {}
        i = 0
        base_got = self.section('.got') - self.base()

        while i < sh.sh_size - 6:
            if self.elfclass == 32:
                # 32-bit
                if code[i:i+2] == b'\xff\x25':
                    # jmp DWORD PTR ds:imm
                    addr_got = u32(code[i+2:i+6])
                    xref[addr_got] = sh.sh_addr + i
                    i += 6
                elif code[i:i+2] == b'\xff\xa3':
                    # jmp DWORD PTR [ebx+imm]
                    addr_got = base_got + u32(code[i+2:i+6])
                    xref[addr_got] = sh.sh_addr + i
                    i += 6
                else:
                    i += 1

            else:
                # 64-bit
                if code[i:i+2] == b'\xff\x25':
                    # jmp QWORD PTR [rip+imm]
                    addr_got = sh.sh_addr + i + 6 + u32(code[i+2:i+6])
                    if i > 4 and code[i-5:i] == b'\xf3\x0f\x1e\xfa\xf2':
                        # endbr64; bnd jmp ...
                        xref[addr_got] = sh.sh_addr + i - 5
                    else:
                        xref[addr_got] = sh.sh_addr + i
                    i += 6
                else:
                    i += 1

        return xref

    def got(self, name):
        """Get a GOT address

        Lookup the GOT table and find the corresponding address

        Args:
            name (str): The function name to find

        Return:
            int: The address of the GOT
        """
        if isinstance(name, str):
            name = str2bytes(name)

        for i in range(self.header.e_shnum):
            section_header = self._get_section(i)
            if section_header.sh_type != 'SHT_REL':
                if section_header.sh_type != 'SHT_RELA':
                    continue

            # Found the relocation section
            symbols = self._get_section(section_header.sh_link)
            for j in range(section_header.sh_size // section_header.sh_entsize):
                rel_offset = section_header.sh_offset + j * section_header.sh_entsize

                if section_header.sh_type == 'SHT_REL':
                    rel = self._parse(
                        self.structs.Elf_Rel,
                        stream_pos = rel_offset
                    )
                else:
                    rel = self._parse(
                        self.structs.Elf_Rela,
                        stream_pos = rel_offset
                    )

                if self.structs.elfclass == 32:
                    sym_idx = rel.r_info >> 8
                else:
                    sym_idx = rel.r_info >> 32
                if not sym_idx:
                    continue

                symbol_name = self._get_symbol_name(symbols, sym_idx)
                if symbol_name == name:
                    return rel.r_offset + (self.base() if self.pie() else 0)

    def main_arena(self):
        """Find main_arena offset

        Returns:
            int: Offset to main_arena (returns None if it's not libc)
        """
        ofs_realloc_hook = self.symbol('__realloc_hook')
        ofs_malloc_hook = self.symbol('__malloc_hook')
        if ofs_realloc_hook is None or ofs_malloc_hook is None:
            logger.warn('main_arena works only for libc binaries')
            return None

        if self.elfclass == 32:
            return ofs_malloc_hook + 0x18
        else:
            return ofs_malloc_hook + (ofs_malloc_hook - ofs_realloc_hook) * 2

    def checksec(self):
        """Check security

        Returns:
            dict: Dictionary of all security information: NX, SSP, RELRO
        """
        class _SecurityInfo(object):
            def __init__(self, elf, nx, ssp, relro, pie):
                self.elf = elf
                self.nx = nx
                self.ssp = ssp
                self.relro = relro
                self.pie = pie

            def __str__(self):
                ret = ''
                ret += Color.BOLD + Color.CYAN + "[*]" + Color.END
                ret += " " + repr(self.elf.filepath) + "\n"
                ret += "    Arch:\t{bit} bits ({endian} endian)\n".format(
                    bit = self.elf.structs.elfclass,
                    endian = 'little' if self.elf.structs.little_endian else 'big'
                )
                # DEP
                if self.nx:
                    ret += "    NX:\t\t{bold}{green}NX enabled{end}\n".format(
                        bold=Color.BOLD, green=Color.GREEN, end=Color.END
                    )
                else:
                    ret += "    NX:\t\t{bold}{red}NX disabled{end}\n".format(
                        bold=Color.BOLD, red=Color.RED, end=Color.END
                    )

                # SSP
                if self.ssp:
                    ret += "    SSP:\t{bold}{green}SSP enabled{end} (Canary found)\n".format(
                        bold=Color.BOLD, green=Color.GREEN, end=Color.END
                    )
                else:
                    ret += "    SSP:\t{bold}{red}SSP disabled{end} (No canary found)\n".format(
                        bold=Color.BOLD, red=Color.RED, end=Color.END
                    )

                # RELRO
                if self.relro == 2:
                    ret += "    RELRO:\t{bold}{green}Full RELRO{end}\n".format(
                        bold=Color.BOLD, green=Color.GREEN, end=Color.END
                    )
                elif self.relro == 1:
                    ret += "    RELRO:\t{bold}{yellow}Partial RELRO{end}\n".format(
                        bold=Color.BOLD, yellow=Color.YELLOW, end=Color.END
                    )
                else:
                    ret += "    RELRO:\t{bold}{red}No RELRO{end}\n".format(
                        bold=Color.BOLD, red=Color.RED, end=Color.END
                    )

                # PIE
                if self.pie:
                    ret += "    PIE:\t{bold}{green}PIE enabled{end}".format(
                        bold=Color.BOLD, green=Color.GREEN, end=Color.END
                    )
                else:
                    ret += "    PIE:\t{bold}{red}PIE disabled{end}".format(
                        bold=Color.BOLD, red=Color.RED, end=Color.END
                    )
                return ret

        return _SecurityInfo(
            elf   = self,
            nx    = self.nx(),
            ssp   = self.ssp(),
            relro = self.relro(),
            pie   = self.pie()
        )

    def ssp(self):
        """Check SSP

        Check if the binary is protected with canary.

        Returns:
            bool: True if enabled, otherwise False.
        """
        if self.got('__stack_chk_fail') is not None:
            return True
        elif self.got('__stack_smash_handler') is not None:
            return True
        else:
            return False

    def pie(self):
        """Check PIE

        Check if PIE is enabled or disabled.

        Returns:
            bool: True if enabled, otherwise False.
        """
        if self._get_tag("EXEC"):
            return False
        if self.header.e_type == "ET_DYN":
            if self._get_tag("DT_DEBUG"):
                return True
            else:
                return True
        return False

    def relro(self):
        """Check RELRO

        Check if RELRO is full/partial enabled or disabled.

        Returns:
            int: 0 if disabled, 1 if partial enabled, and 2 if fully enabled.
        """
        for i in range(self.header.e_phnum):
            segment_header = self._get_segment(i)
            if segment_header.p_type == "PT_GNU_RELRO":
                break
        else:
            return 0
        flags = self._get_tag("DT_FLAGS")
        flags_1 = self._get_tag("DT_FLAGS_1")
        if self._get_tag("DT_BIND_NOW"):
            return 2
        elif flags and flags.d_un & 0x8:
            return 2
        elif flags_1 and flags_1.d_un & 0x8:
            return 2
        else:
            return 1

    def nx(self):
        """Check NX bit

        Check if NX bit is enabled.

        Returns:
            bool: True if NX is enabled
        """
        for i in range(self.header.e_phnum):
            segment_header = self._get_segment(i)
            if segment_header.p_type == "PT_GNU_STACK":
                if segment_header.p_flags & 1:
                    # Executable
                    return False
                return True
        return False

    def _get_tag(self, key):
        for i in range(self.header.e_shnum):
            section_header = self._get_section(i)
            if section_header.sh_type != "SHT_DYNAMIC":
                continue

            i = 0
            while True:
                tag = self._parse(
                    self.structs.Elf_Dyn,
                    stream_pos = section_header.sh_offset + i * self.structs.Elf_Dyn.sizeof()
                )
                if tag.d_tag == key:
                    return tag
                elif tag.d_tag == 'DT_NULL':
                    break
                i += 1
        return False

    def _get_segment(self, n):
        return self._parse(
            self.structs.Elf_Phdr,
            stream_pos = self.header.e_phoff + n * self.header.e_phentsize
        )

    def _get_section(self, n):
        return self._parse(
            self.structs.Elf_Shdr,
            stream_pos = self.header.e_shoff + n * self.header.e_shentsize
        )

    def _get_section_by_name(self, name):
        head = self.section_string.sh_offset

        for i in range(self.header.e_shnum):
            section_header = self._get_section(i)
            name_offset = section_header.sh_name
            section_name = self._get_string(head + name_offset)

            if section_name == name:
                return section_header

        return None
    
    def _identify(self):
        """Check the endian and class of the ELF
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
            logger.warning("Invalid EI_CLASS")
            return False

        ei_data = self.stream.read(1)
        if ei_data == b'\x01':
            self.little_endian = True
        elif ei_data == b'\x02':
            self.little_endian = False
        else:
            logger.warning("Invalid EI_DATA")
            return False

        return True

    def _get_symbol_name(self, symbols, n):
        section_strtab = self._get_section(symbols.sh_link)
        sym_offset = symbols.sh_offset + n * symbols.sh_entsize
        sym = self._parse(
            self.structs.Elf_Sym,
            stream_pos = sym_offset
        )
        return self._get_string(section_strtab.sh_offset + sym.st_name)

    def _get_string(self, stream_pos):
        self.stream.seek(stream_pos)
        chunks = []
        found = False
        while True:
            chunk = self.stream.read(64)
            ei = chunk.find(b'\x00')
            if ei >= 0:
                chunks.append(chunk[:ei])
                found = True
                break
            else:
                chunks.append(chunk)
            if len(chunk) < 64:
                break
        return b''.join(chunks) if found else None

    def _parse(self, struct, stream_pos=None):
        try:
            if stream_pos is not None:
                self.stream.seek(stream_pos)
            return struct.parse_stream(self.stream)
        except ConstructError:
            logger.warning("Parse Error")
            exit(1)  # CHECK:

    def close(self):
        if self.stream:
            self.stream.close()
        del self
