import functools
from ptrlib.filestruct.bunkai import *
from .enums import *

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache

@cache
def Elf_Ehdr(parser):
    return 'Elf_ESR' <= Struct(
        'e_ident' <= Struct(
            'EI_MAG'     <= Array(4, parser.Elf_Byte),
            'EI_CLASS'   <= Enum(parser.Elf_Byte, **ENUM_EI_CLASS),
            'EI_DATA'    <= Enum(parser.Elf_Byte, **ENUM_EI_DATA),
            'EI_VERSION' <= Enum(parser.Elf_Byte, **ENUM_E_VERSION),
            'EI_OSABI'   <= Enum(parser.Elf_Byte, **ENUM_EI_OSABI),
            'EI_ABIVERSION' <= parser.Elf_Byte,
            '_pad' <= Array(7, parser.Elf_Byte)
        ),
        'e_type'      <= Enum(parser.Elf_Half, **ENUM_E_TYPE),
        'e_machine'   <= Enum(parser.Elf_Half, **ENUM_E_MACHINE),
        'e_version'   <= Enum(parser.Elf_Word, **ENUM_E_VERSION),
        'e_entry'     <= parser.Elf_Addr,
        'e_phoff'     <= parser.Elf_Offset,
        'e_shoff'     <= parser.Elf_Offset,
        'e_flags'     <= parser.Elf_Word,
        'e_ehsize'    <= parser.Elf_Half,
        'e_phentsize' <= parser.Elf_Half,
        'e_phnum'     <= parser.Elf_Half,
        'e_shentsize' <= parser.Elf_Half,
        'e_shnum'     <= parser.Elf_Half,
        'e_shstrndx'  <= parser.Elf_Half,
    )

@cache
def Elf_Phdr(parser):
    e_machine = parser.ehdr['e_machine']
    p_type_dict = ENUM_P_TYPE_BASE
    if e_machine == 'EM_ARM':
        p_type_dict = ENUM_P_TYPE_ARM
    elif e_machine == 'EM_AARCH64':
        p_type_dict = ENUM_P_TYPE_AARCH64
    elif e_machine == 'EM_MIPS':
        p_type_dict = ENUM_P_TYPE_MIPS

    if parser.elfclass == 32:
        return 'Elf_Phdr' <= Struct(
            'p_type'   <= Enum(parser.Elf_Word, **p_type_dict),
            'p_offset' <= parser.Elf_Offset,
            'p_vaddr'  <= parser.Elf_Addr,
            'p_paddr'  <= parser.Elf_Addr,
            'p_filesz' <= parser.Elf_Word,
            'p_memsz'  <= parser.Elf_Word,
            'p_flags'  <= parser.Elf_Word,
            'p_align'  <= parser.Elf_Word,
        )
    else:
        return 'Elf_Phdr' <= Struct(
            'p_type'   <= Enum(parser.Elf_Word, **p_type_dict),
            'p_flags'  <= parser.Elf_Word,
            'p_offset' <= parser.Elf_Offset,
            'p_vaddr'  <= parser.Elf_Addr,
            'p_paddr'  <= parser.Elf_Addr,
            'p_filesz' <= parser.Elf_Xword,
            'p_memsz'  <= parser.Elf_Xword,
            'p_align'  <= parser.Elf_Xword,
        )

@cache
def Elf_Shdr(parser):
    sh_type_dict = ENUM_SH_TYPE_BASE
    e_machine = parser.ehdr['e_machine']
    if e_machine == 'EM_ARM':
        sh_type_dict = ENUM_SH_TYPE_ARM
    elif e_machine == 'EM_X86_64':
        sh_type_dict = ENUM_SH_TYPE_AMD64
    elif e_machine == 'EM_MIPS':
        sh_type_dict = ENUM_SH_TYPE_MIPS

    return 'Elf_Shdr' <= Struct(
        'sh_name'      <= parser.Elf_Word,
        'sh_type'      <= Enum(parser.Elf_Word, **sh_type_dict),
        'sh_flags'     <= parser.Elf_Xword,
        'sh_addr'      <= parser.Elf_Addr,
        'sh_offset'    <= parser.Elf_Offset,
        'sh_size'      <= parser.Elf_Xword,
        'sh_link'      <= parser.Elf_Word,
        'sh_info'      <= parser.Elf_Word,
        'sh_addralign' <= parser.Elf_Xword,
        'sh_entsize'   <= parser.Elf_Xword,
    )

@cache
def Elf_Chdr(parser):
    fields = [
        'ch_type'      <= Enum(parser.Elf_Word, **ENUM_ELFCOMPRESS_TYPE),
        'ch_size'      <= parser.Elf_Xword,
        'ch_addralign' <= parser.Elf_Xword,
    ]
    if parser.elfclass == 64:
        fields.insert(1, 'ch_reserved' <= parser.Elf_Word)
    return 'Elf_Chdr' <= Struct(*fields)

@cache
def Elf_Rel(parser):
    return 'Elf_Rel' <= Struct(
        'r_offset' <= parser.Elf_Addr,
        'r_info'   <= parser.Elf_Xword,
    )

@cache
def Elf_Rela(parser):
    return 'Elf_Rela' <= Struct(
        'r_offset' <= parser.Elf_Addr,
        'r_info'   <= parser.Elf_Xword,
        'r_addend' <= parser.Elf_Sxword,
    )

@cache
def Elf_Dyn(parser):
    e_machine = parser.ehdr['e_machine']
    e_ident_osabi = parser.ehdr['e_ident']['EI_OSABI']
    d_tag_dict = dict(ENUM_D_TAG_COMMON)
    if e_machine in ENUMMAP_EXTRA_D_TAG_MACHINE:
        d_tag_dict.update(ENUMMAP_EXTRA_D_TAG_MACHINE[e_machine])
    elif e_ident_osabi == 'ELFOSABI_SOLARIS':
        d_tag_dict.update(ENUM_D_TAG_SOLARIS)

    return 'Elf_Dyn' <= Struct(
        'd_tag' <= Enum(parser.Elf_Sxword, **d_tag_dict),
        'd_un'  <= parser.Elf_Xword
    )

@cache
def Elf_Sym(parser):
    st_info_struct = 'st_info' <= BitStruct(
        'bind' <= BitInt(4),
        'type' <= BitInt(4)
    )
    st_other_struct = 'st_other' <= BitStruct(
        '_' <= BitInt(5),
        'visibility' <= BitInt(3)
    )
    if parser.elfclass == 32:
        return 'Elf_Sym' <= Struct(
            'st_name'  <= parser.Elf_Word,
            'st_value' <= parser.Elf_Addr,
            'st_size'  <= parser.Elf_Word,
            st_info_struct,
            st_other_struct,
            'st_shndx' <= Enum(parser.Elf_Half, **ENUM_ST_SHNDX),
        )
    else:
        return 'Elf_Sym' <= Struct(
            'st_name'  <= parser.Elf_Word,
            st_info_struct,
            st_other_struct,
            'st_shndx' <= Enum(parser.Elf_Half, **ENUM_ST_SHNDX),
            'st_value' <= parser.Elf_Addr,
            'st_size'  <= parser.Elf_Xword,
        )
