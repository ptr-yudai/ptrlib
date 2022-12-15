import functools
from .structs import *

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


class ELFParser(object):
    def __init__(self, filepath):
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
        e_ident_osabi = self.ehdr['e_ident']['EI_OSABI']

        """
        # Elf_Uleb128 (without converter)
        self.Elf_Uleb128 = VariableArray(lambda c,_: c<0x80, u8)

        # C-string
        self.Elf_ntbs = VariableArray(lambda c,_: c!=0, u8)
        """

    @cache
    def section_by_name(self, name):
        head = self.section_at(self.ehdr['e_shstrndx'])['sh_offset']

        for i in range(self.ehdr['e_shnum']):
            shdr = self.section_at(i)
            section_name = self.string_at(head + shdr['sh_name'])

            if section_name == name:
                return shdr

        return None

    @cache
    def section_at(self, n):
        self.stream.seek(self.ehdr['e_shoff'] + n * self.ehdr['e_shentsize'])
        return Elf_Shdr(self).parse_stream(self.stream)

    @cache
    def segment_at(self, n):
        self.stream.seek(self.ehdr['e_phoff'] + n * self.ehdr['e_phentsize'])
        return Elf_Phdr(self).parse_stream(self.stream)

    @cache
    def string_at(self, offset):
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

    def iter_sections(self):
        for n in range(self.ehdr['e_shnum']):
            yield self.section_at(n)

    def iter_symtab(self, shdr):
        for j in range(1, shdr['sh_size'] // shdr['sh_entsize']):
            self.stream.seek(shdr['sh_offset'] + j * shdr['sh_entsize'])
            yield Elf_Sym(self).parse_stream(self.stream)

    def iter_rel(self):
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
    def segments(self, writable=None, executable=None):
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
    def tag(self, key):
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
                elif tag['d_tag'] == 'DT_NULL':
                    break
                i += 1

        return False

    def symbol_name(self, symbols, n):
        strtab = self.section_at(symbols['sh_link'])
        self.stream.seek(symbols['sh_offset'] + n * symbols['sh_entsize'])
        symtab = Elf_Sym(self).parse_stream(self.stream)
        return self.string_at(strtab['sh_offset'] + symtab['st_name'])

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
