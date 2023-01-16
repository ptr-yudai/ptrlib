from logging import getLogger
from typing import Mapping, Tuple
from ptrlib.binary.packing import *
from ptrlib.filestruct.elf.elf import ELF

logger = getLogger(__name__)


def struct_ret2dl(addrList: Mapping[str, int], elf: ELF, base: Optional[int]=None) -> Tuple[int, bytes, bytes]:
    """
    Args:
        addrList (int): Address to put reloc, sym, symstr
        elf (ELF)  : Target ELF
        base (int) : PIE base if PIE is enabled
    """
    if not elf.pie():
        proc_base = 0
    elif base:
        proc_base = base
    else:
        logger.warning("PIE base is unknown. Set 0 if you handle it by yourself.")
        logger.warning("In that case make sure `reloc` is offset from PIE base.")
        raise ValueError("Lack of information")
    
    addr_dynsym = elf._offset_section('.dynsym')
    addr_dynstr = elf._offset_section('.dynstr')
    addr_relplt = elf._offset_section('.rel.plt')
    if  addr_dynsym is None or \
        addr_dynstr is None or \
        addr_relplt is None:
        logger.warning("Some required section dosen't exist.")
        raise ValueError("Lack of information")
    addr_dynsym += proc_base
    addr_dynstr += proc_base
    addr_relplt += proc_base

    addr_reloc  = addrList['reloc']
    addr_sym    = addrList['sym']
    addr_symstr = addrList['symstr']
    addr_got    = addrList['got']

    if addr_sym & 0xF != addr_dynsym & 0xF:
        logger.error("addr_sym & 0xf must be {}".format(hex(addr_dynsym & 0xF)))
        addr_sym += 0x10 - ((addr_sym - addr_dynsym) & 0xF)
        logger.error("It should be {}".format(hex(addr_sym)))

    if elf.elfclass == 32:
        reloc  = p32(addr_got)
        reloc += p32(((addr_sym - addr_dynsym) << 4) & ~0xFF | 7)
        sym  = p32(addr_symstr - addr_dynstr)
        sym += p32(0)
        sym += p32(0)
        sym += p32(0x12)
    else:
        logger.warning("Not implemented yet!")
        raise NotImplementedError()
    
    return addr_reloc - addr_relplt, reloc, sym
