from .enums import *
from ptrlib.filestruct.bunkai import *

class ELFFile(object):
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
        self.Elf_Ehdr = 'Elf_Ehdr' <= Struct(
            'e_ident' <= Struct(
                'EI_MAG'     <= Array(4, self.Elf_Byte),
                'EI_CLASS'   <= Enum(self.Elf_Byte, **ENUM_EI_CLASS),
                'EI_DATA'    <= Enum(self.Elf_Byte, **ENUM_EI_DATA),
                'EI_VERSION' <= Enum(self.Elf_Byte, **ENUM_E_VERSION),
                'EI_OSABI'   <= Enum(self.Elf_Byte, **ENUM_EI_OSABI),
                'EI_ABIVERSION' <= self.Elf_Byte,
                '_pad' <= Array(7, self.Elf_Byte)
            ),
            'e_type'      <= Enum(self.Elf_Half, **ENUM_E_TYPE),
            'e_machine'   <= Enum(self.Elf_Half, **ENUM_E_MACHINE),
            'e_version'   <= Enum(self.Elf_Word, **ENUM_E_VERSION),
            'e_entry'     <= self.Elf_Addr,
            'e_phoff'     <= self.Elf_Offset,
            'e_shoff'     <= self.Elf_Offset,
            'e_flags'     <= self.Elf_Word,
            'e_ehsize'    <= self.Elf_Half,
            'e_phentsize' <= self.Elf_Half,
            'e_phnum'     <= self.Elf_Half,
            'e_shentsize' <= self.Elf_Half,
            'e_shnum'     <= self.Elf_Half,
            'e_shstrndx'  <= self.Elf_Half,
        )
        self.ehdr = self.Elf_Ehdr.parse_stream(self.stream)
        e_machine = self.ehdr['e_machine']
        e_ident_osabi = self.ehdr['e_ident']['EI_OSABI']

        # Program header
        p_type_dict = ENUM_P_TYPE_BASE
        if e_machine == 'EM_ARM':
            p_type_dict = ENUM_P_TYPE_ARM
        elif e_machine == 'EM_AARCH64':
            p_type_dict = ENUM_P_TYPE_AARCH64
        elif e_machine == 'EM_MIPS':
            p_type_dict = ENUM_P_TYPE_MIPS

        if self.elfclass == 32:
            self.Elf_Phdr = 'Elf_Phdr' <= Struct(
                'p_type'   <= Enum(self.Elf_Word, **p_type_dict),
                'p_offset' <= self.Elf_Offset,
                'p_vaddr'  <= self.Elf_Addr,
                'p_paddr'  <= self.Elf_Addr,
                'p_filesz' <= self.Elf_Word,
                'p_memsz'  <= self.Elf_Word,
                'p_flags'  <= self.Elf_Word,
                'p_align'  <= self.Elf_Word,
            )
        else: # 64
            self.Elf_Phdr = 'Elf_Phdr' <= Struct(
                'p_type'   <= Enum(self.Elf_Word, **p_type_dict),
                'p_flags'  <= self.Elf_Word,
                'p_offset' <= self.Elf_Offset,
                'p_vaddr'  <= self.Elf_Addr,
                'p_paddr'  <= self.Elf_Addr,
                'p_filesz' <= self.Elf_Xword,
                'p_memsz'  <= self.Elf_Xword,
                'p_align'  <= self.Elf_Xword,
            )

        # Section header
        sh_type_dict = ENUM_SH_TYPE_BASE
        if e_machine == 'EM_ARM':
            sh_type_dict = ENUM_SH_TYPE_ARM
        elif e_machine == 'EM_X86_64':
            sh_type_dict = ENUM_SH_TYPE_AMD64
        elif e_machine == 'EM_MIPS':
            sh_type_dict = ENUM_SH_TYPE_MIPS

        self.Elf_Shdr = 'Elf_Shdr' <= Struct(
            'sh_name'      <= self.Elf_Word,
            'sh_type'      <= Enum(self.Elf_Word, **sh_type_dict),
            'sh_flags'     <= self.Elf_Xword,
            'sh_addr'      <= self.Elf_Addr,
            'sh_offset'    <= self.Elf_Offset,
            'sh_size'      <= self.Elf_Xword,
            'sh_link'      <= self.Elf_Word,
            'sh_info'      <= self.Elf_Word,
            'sh_addralign' <= self.Elf_Xword,
            'sh_entsize'   <= self.Elf_Xword,
        )

        # Compressed section header
        fields = [
            'ch_type'      <= Enum(self.Elf_Word, **ENUM_ELFCOMPRESS_TYPE),
            'ch_size'      <= self.Elf_Xword,
            'ch_addralign' <= self.Elf_Xword,
        ]
        if self.elfclass == 64:
            fields.insert(1, 'ch_reserved' <= self.Elf_Word)
        self.Elf_Chdr = 'Elf_Chdr' <= Struct(*fields)

        # Rel / Rela section
        # TODO: Check if this is correct
        self.Elf_Rel = 'Elf_Rel' <= Struct(
            'r_offset' <= self.Elf_Addr,
            'r_info'   <= self.Elf_Xword,
        )
        self.Elf_Rela = 'Elf_Rela' <= Struct(
            'r_offset' <= self.Elf_Addr,
            'r_info'   <= self.Elf_Xword,
            'r_addend' <= self.Elf_Sxword,
        )

        # Dyn section
        d_tag_dict = dict(ENUM_D_TAG_COMMON)
        if e_machine in ENUMMAP_EXTRA_D_TAG_MACHINE:
            d_tag_dict.update(ENUMMAP_EXTRA_D_TAG_MACHINE[e_machine])
        elif e_ident_osabi == 'ELFOSABI_SOLARIS':
            d_tag_dict.update(ENUM_D_TAG_SOLARIS)
        self.Elf_Dyn = 'Elf_Dyn' <= Struct(
            'd_tag' <= Enum(self.Elf_Sxword, **d_tag_dict),
            'd_un'  <= self.Elf_Xword
        )

        """
        # Elf_Uleb128 (without converter)
        self.Elf_Uleb128 = VariableArray(lambda c,_: c<0x80, u8)

        # C-string
        self.Elf_ntbs = VariableArray(lambda c,_: c!=0, u8)
        """

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
