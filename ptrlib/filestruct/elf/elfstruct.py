#-------------------------------------------------------------------------------
# This is the revision of pyelftools (for newer version of Construct)
#
# Encapsulation of Construct structs for parsing an ELF file, adjusted for
# correct endianness and word-size.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from ptrlib.util.construct import *
from ptrlib.executable.elfenums import *

class ELFStructs(object):
    """ Accessible attributes:

            Elf_{byte|half|word|word64|addr|offset|sword|xword|xsword}:
                Data chunks, as specified by the ELF standard, adjusted for
                correct endianness and word-size.

            Elf_Ehdr:
                ELF file header

            Elf_Phdr:
                Program header

            Elf_Shdr:
                Section header

            Elf_Sym:
                Symbol table entry

            Elf_Rel, Elf_Rela:
                Entries in relocation sections
    """
    def __init__(self, little_endian=True, elfclass=32):
        assert elfclass == 32 or elfclass == 64
        self.little_endian = little_endian
        self.elfclass = elfclass

    def create_basic_structs(self):
        """ Create word-size related structs and ehdr struct needed for
            initial determining of ELF type.
        """
        if self.little_endian:
            self.Elf_Byte = Int8ul
            self.Elf_Half = Int16ul
            self.Elf_Word = Int32ul
            self.Elf_Word64 = Int64ul
            self.Elf_Addr = Int32ul if self.elfclass == 32 else Int64ul
            self.Elf_Offset = self.Elf_Addr
            self.Elf_Sword = Int32sl
            self.Elf_Xword = Int32ul if self.elfclass == 32 else Int64ul
            self.Elf_Sxword = Int32sl if self.elfclass == 32 else Int64sl
        else:
            self.Elf_Byte = Int8ub
            self.Elf_Half = Int16ub
            self.Elf_Word = Int32ub
            self.Elf_Word64 = Int64ub
            self.Elf_Addr = Int32ub if self.elfclass == 32 else Int64ub
            self.Elf_Offset = self.Elf_Addr
            self.Elf_Sword = Int32sb
            self.Elf_Xword = Int32ub if self.elfclass == 32 else Int64ub
            self.Elf_Sxword = Int32sb if self.elfclass == 32 else Int64sb
        self._create_ehdr()
        self._create_leb128()
        self._create_ntbs()

    def create_advanced_structs(self, e_type=None, e_machine=None, e_ident_osabi=None):
        """ Create all ELF structs except the ehdr. They may possibly depend
            on provided e_type and/or e_machine parsed from ehdr.
        """
        self._create_phdr(e_machine)
        self._create_shdr(e_machine)
        self._create_chdr()
        self._create_sym()
        self._create_rel()
        self._create_dyn(e_machine, e_ident_osabi)
        self._create_sunw_syminfo()
        self._create_gnu_verneed()
        self._create_gnu_verdef()
        self._create_gnu_versym()
        self._create_gnu_abi()
        self._create_note(e_type)
        self._create_stabs()
        self._create_arm_attributes()

    #-------------------------------- PRIVATE --------------------------------#

    def _create_ehdr(self):
        self.Elf_Ehdr = 'Elf_Ehdr' / Struct(
            'e_ident' / Struct(
                'EI_MAG'     / Array(4, self.Elf_Byte),
                'EI_CLASS'   / Enum(self.Elf_Byte, **ENUM_EI_CLASS),
                'EI_DATA'    / Enum(self.Elf_Byte, **ENUM_EI_DATA),
                'EI_VERSION' / Enum(self.Elf_Byte, **ENUM_E_VERSION),
                'EI_OSABI'   / Enum(self.Elf_Byte, **ENUM_EI_OSABI),
                'EI_ABIVERSION' / self.Elf_Byte,
                Padding(7)
            ),
            'e_type'      / Enum(self.Elf_Half, **ENUM_E_TYPE),
            'e_machine'   / Enum(self.Elf_Half, **ENUM_E_MACHINE),
            'e_version'   / Enum(self.Elf_Word, **ENUM_E_VERSION),
            'e_entry'     / self.Elf_Addr,
            'e_phoff'     / self.Elf_Offset,
            'e_shoff'     / self.Elf_Offset,
            'e_flags'     / self.Elf_Word,
            'e_ehsize'    / self.Elf_Half,
            'e_phentsize' / self.Elf_Half,
            'e_phnum'     / self.Elf_Half,
            'e_shentsize' / self.Elf_Half,
            'e_shnum'     / self.Elf_Half,
            'e_shstrndx'  / self.Elf_Half,
        )

    def _create_leb128(self):
        self.Elf_Uleb128 = _ULEB128Adapter(
            RepeatUntil(
                lambda obj, ctx: ord(obj) < 0x80,
                Byte
            )
        )

    def _create_ntbs(self):
        self.Elf_ntbs = CString

    def _create_phdr(self, e_machine=None):
        p_type_dict = ENUM_P_TYPE_BASE
        if e_machine == 'EM_ARM':
            p_type_dict = ENUM_P_TYPE_ARM
        elif e_machine == 'EM_AARCH64':
            p_type_dict = ENUM_P_TYPE_AARCH64
        elif e_machine == 'EM_MIPS':
            p_type_dict = ENUM_P_TYPE_MIPS

        if self.elfclass == 32:
            self.Elf_Phdr = 'Elf_Phdr' / Struct(
                'p_type'   / Enum(self.Elf_Word, **p_type_dict),
                'p_offset' / self.Elf_Offset,
                'p_vaddr'  / self.Elf_Addr,
                'p_paddr'  / self.Elf_Addr,
                'p_filesz' / self.Elf_Word,
                'p_memsz'  / self.Elf_Word,
                'p_flags'  / self.Elf_Word,
                'p_align'  / self.Elf_Word,
            )
        else: # 64
            self.Elf_Phdr = 'Elf_Phdr' / Struct(
                'p_type'   / Enum(self.Elf_Word, **p_type_dict),
                'p_flags'  / self.Elf_Word,
                'p_offset' / self.Elf_Offset,
                'p_vaddr'  / self.Elf_Addr,
                'p_paddr'  / self.Elf_Addr,
                'p_filesz' / self.Elf_Xword,
                'p_memsz'  / self.Elf_Xword,
                'p_align'  / self.Elf_Xword,
            )

    def _create_shdr(self, e_machine=None):
        """Section header parsing.

        Depends on e_machine because of machine-specific values in sh_type.
        """
        sh_type_dict = ENUM_SH_TYPE_BASE
        if e_machine == 'EM_ARM':
            sh_type_dict = ENUM_SH_TYPE_ARM
        elif e_machine == 'EM_X86_64':
            sh_type_dict = ENUM_SH_TYPE_AMD64
        elif e_machine == 'EM_MIPS':
            sh_type_dict = ENUM_SH_TYPE_MIPS

        self.Elf_Shdr = 'Elf_Shdr' / Struct(
            'sh_name'      / self.Elf_Word,
            'sh_type'      / Enum(self.Elf_Word, **sh_type_dict),
            'sh_flags'     / self.Elf_Xword,
            'sh_addr'      / self.Elf_Addr,
            'sh_offset'    / self.Elf_Offset,
            'sh_size'      / self.Elf_Xword,
            'sh_link'      / self.Elf_Word,
            'sh_info'      / self.Elf_Word,
            'sh_addralign' / self.Elf_Xword,
            'sh_entsize'   / self.Elf_Xword,
        )

    def _create_chdr(self):
        # Structure of compressed sections header. It is documented in Oracle
        # "Linker and Libraries Guide", Part IV ELF Application Binary
        # Interface, Chapter 13 Object File Format, Section Compression:
        # https://docs.oracle.com/cd/E53394_01/html/E54813/section_compression.html
        fields = [
            'ch_type'      / Enum(self.Elf_Word, **ENUM_ELFCOMPRESS_TYPE),
            'ch_size'      / self.Elf_Xword,
            'ch_addralign' / self.Elf_Xword,
        ]
        if self.elfclass == 64:
            fields.insert(1, 'ch_reserved' / self.Elf_Word)
        self.Elf_Chdr = 'Elf_Chdr' / Struct(*fields)

    def _create_rel(self):
        # r_info is also taken apart into r_info_sym and r_info_type.
        # This is done in Value to avoid endianity issues while parsing.
        """
        if self.elfclass == 32:
            r_info_sym = 'r_info_sym' / Value(
                lambda ctx: (ctx['r_info'] >> 8) & 0xFFFFFF
            )
            r_info_type = 'r_info_type' / Value(
                lambda ctx: ctx['r_info'] & 0xFF
            )
        else: # 64
            r_info_sym = 'r_info_sym' / Value(
                lambda ctx: (ctx['r_info'] >> 32) & 0xFFFFFFFF
            )
            r_info_type = 'r_info_type' / Value(
                lambda ctx: ctx['r_info'] & 0xFFFFFFFF
            )
        """
        self.Elf_Rel = 'Elf_Rel' / Struct(
            'r_offset' / self.Elf_Addr,
            'r_info' / self.Elf_Xword,
            #r_info_sym,
            #r_info_type,
        )
        self.Elf_Rela = 'Elf_Rela' / Struct(
            'r_offset' / self.Elf_Addr,
            'r_info' / self.Elf_Xword,
            #r_info_sym,
            #r_info_type,
            'r_addend' / self.Elf_Sxword,
        )

    def _create_dyn(self, e_machine=None, e_ident_osabi=None):
        d_tag_dict = dict(ENUM_D_TAG_COMMON)
        if e_machine in ENUMMAP_EXTRA_D_TAG_MACHINE:
            d_tag_dict.update(ENUMMAP_EXTRA_D_TAG_MACHINE[e_machine])
        elif e_ident_osabi == 'ELFOSABI_SOLARIS':
            d_tag_dict.update(ENUM_D_TAG_SOLARIS)

        self.Elf_Dyn = 'Elf_Dyn' / Struct(
            'd_tag' / Enum(self.Elf_Sxword, **d_tag_dict),
            'd_un' / self.Elf_Xword
        )
        """
        'd_un' / Union(
        None,
        'd_val' / self.Elf_Xword,
        'd_ptr' / self.Elf_Addr,
        )
        """

    def _create_sym(self):
        # st_info is hierarchical. To access the type, use
        # container['st_info']['type']
        st_info_struct = 'st_info' / BitStruct(
            Enum('bind' / BitsInteger(4), **ENUM_ST_INFO_BIND),
            Enum('type' / BitsInteger(4), **ENUM_ST_INFO_TYPE))
        # st_other is hierarchical. To access the visibility,
        # use container['st_other']['visibility']
        st_other_struct = 'st_other' / BitStruct(
            Padding(5),
            'visibility' / Enum(BitsInteger(3), **ENUM_ST_VISIBILITY))
        if self.elfclass == 32:
            self.Elf_Sym = 'Elf_Sym' / Struct(
                'st_name'  / self.Elf_Word,
                'st_value' / self.Elf_Addr,
                'st_size'  / self.Elf_Word,
                st_info_struct,
                st_other_struct,
                'st_shndx' / Enum(self.Elf_Half, **ENUM_ST_SHNDX),
            )
        else:
            self.Elf_Sym = 'Elf_Sym' / Struct(
                'st_name'  / self.Elf_Word,
                st_info_struct,
                st_other_struct,
                'st_shndx' / Enum(self.Elf_Half, **ENUM_ST_SHNDX),
                'st_value' / self.Elf_Addr,
                'st_size'  / self.Elf_Xword,
            )

    def _create_sunw_syminfo(self):
        self.Elf_Sunw_Syminfo = 'Elf_Sunw_Syminfo' / Struct(
            'si_boundto' / Enum(self.Elf_Half, **ENUM_SUNW_SYMINFO_BOUNDTO),
            'si_flags'   / self.Elf_Half,
        )

    def _create_gnu_verneed(self):
        # Structure of "version needed" entries is documented in
        # Oracle "Linker and Libraries Guide", Chapter 13 Object File Format
        self.Elf_Verneed = 'Elf_Verneed' / Struct(
            'vn_version' / self.Elf_Half,
            'vn_cnt'     / self.Elf_Half,
            'vn_file'    / self.Elf_Word,
            'vn_aux'     / self.Elf_Word,
            'vn_next'    / self.Elf_Word,
        )
        self.Elf_Vernaux = 'Elf_Vernaux' / Struct(
            'vna_hash'  / self.Elf_Word,
            'vna_flags' / self.Elf_Half,
            'vna_other' / self.Elf_Half,
            'vna_name'  / self.Elf_Word,
            'vna_next'  / self.Elf_Word,
        )

    def _create_gnu_verdef(self):
        # Structure of "version definition" entries are documented in
        # Oracle "Linker and Libraries Guide", Chapter 13 Object File Format
        self.Elf_Verdef = 'Elf_Verdef' / Struct(
            'vd_version' / self.Elf_Half,
            'vd_flags'   / self.Elf_Half,
            'vd_ndx'     / self.Elf_Half,
            'vd_cnt'     / self.Elf_Half,
            'vd_hash'    / self.Elf_Word,
            'vd_aux'     / self.Elf_Word,
            'vd_next'    / self.Elf_Word,
        )
        self.Elf_Verdaux = 'Elf_Verdaux' / Struct(
            'vda_name' / self.Elf_Word,
            'vda_next' / self.Elf_Word,
        )

    def _create_gnu_versym(self):
        # Structure of "version symbol" entries are documented in
        # Oracle "Linker and Libraries Guide", Chapter 13 Object File Format
        self.Elf_Versym = 'Elf_Versym' / Struct(
            'ndx' / Enum(self.Elf_Half, **ENUM_VERSYM),
        )

    def _create_gnu_abi(self):
        # Structure of GNU ABI notes is documented in
        # https://code.woboq.org/userspace/glibc/csu/abi-note.S.html
        self.Elf_abi = 'Elf_abi' / Struct(
            'abi_os'    / Enum(self.Elf_Word, **ENUM_NOTE_ABI_TAG_OS),
            'abi_major' / self.Elf_Word,
            'abi_minor' / self.Elf_Word,
            'abi_tiny'  / self.Elf_Word,
        )

    def _create_note(self, e_type=None):
        # Structure of "PT_NOTE" section
        self.Elf_Nhdr = 'Elf_Nhdr' / Struct(
            'n_namesz' / self.Elf_Word,
            'n_descsz' / self.Elf_Word,
            'n_type'   / Enum(self.Elf_Word,
                              **(ENUM_NOTE_N_TYPE if e_type != "ET_CORE"
                                 else ENUM_CORE_NOTE_N_TYPE)),
        )

        # A process psinfo structure according to
        # http://elixir.free-electrons.com/linux/v2.6.35/source/include/linux/elfcore.h#L84
        if self.elfclass == 32:
            self.Elf_Prpsinfo = 'Elf_Prpsinfo' / Struct(
                'pr_state'  / self.Elf_Byte,
                'pr_sname'  / self.Elf_Byte,
                'pr_zomb'   / self.Elf_Byte,
                'pr_nice'   / self.Elf_Byte,
                'pr_flag'   / self.Elf_Xword,
                'pr_uid'    / self.Elf_Half,
                'pr_gid'    / self.Elf_Half,
                'pr_pid'    / self.Elf_Half,
                'pr_ppid'   / self.Elf_Half,
                'pr_pgrp'   / self.Elf_Half,
                'pr_sid'    / self.Elf_Half,
                'pr_fname'  / Bytes(16),
                'pr_psargs' / Bytes(80),
            )
        else: # 64
            self.Elf_Prpsinfo = 'Elf_Prpsinfo' / Struct(
                'pr_state'  / self.Elf_Byte,
                'pr_sname'  / self.Elf_Byte,
                'pr_zomb'   / self.Elf_Byte,
                'pr_nice'   / self.Elf_Byte,
                Padding(4),
                'pr_flag'   / self.Elf_Xword,
                'pr_uid'    / self.Elf_Word,
                'pr_gid'    / self.Elf_Word,
                'pr_pid'    / self.Elf_Word,
                'pr_ppid'   / self.Elf_Word,
                'pr_pgrp'   / self.Elf_Word,
                'pr_sid'    / self.Elf_Word,
                'pr_fname'  / Bytes(16),
                'pr_psargs' / Bytes(80),
            )

    def _create_stabs(self):
        # Structure of one stabs entry, see binutils/bfd/stabs.c
        # Names taken from https://sourceware.org/gdb/current/onlinedocs/stabs.html#Overview
        self.Elf_Stabs = 'Elf_Stabs' / Struct(
            'n_strx'  / self.Elf_Word,
            'n_type'  / self.Elf_Byte,
            'n_other' / self.Elf_Byte,
            'n_desc'  / self.Elf_Half,
            'n_value' / self.Elf_Word,
        )

    def _create_arm_attributes(self):
        # Structure of a build attributes subsection header. A subsection is
        # either public to all tools that process the ELF file or private to
        # the vendor's tools.
        self.Elf_Attr_Subsection_Header = 'Elf_Attr_Subsection' / Struct(
            'length' / self.Elf_Word,
            'vendor_name' / self.Elf_ntbs(encoding='utf-8')
        )

        # Structure of a build attribute tag.
        self.Elf_Attribute_Tag = 'Elf_Attribute_Tag' / Struct(
            'tag' / Enum(self.Elf_Uleb128, **ENUM_ATTR_TAG_ARM)
        )


class _ULEB128Adapter(Adapter):
    """ An adapter for ULEB128, given a sequence of bytes in a sub-construct.
    """
    def _decode(self, obj, context, path):
        value = 0
        for b in reversed(obj):
            value = (value << 7) + (ord(b) & 0x7F)
        return value

    def _encode(self, obj, context, path):
        pass
