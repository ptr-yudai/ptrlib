#!/usr/bin/env python3
from ptrlib import *

# `nasm` is useful for Intel architecture
# You can use nsam macro such as db
print(nasm("""
  call X
  db "Hello", 0
X:
  pop rax
""", bits=64).hex())

# Intel 32-bit
print(assemble("""
  xor edx, edx
  mov eax, [esp]
  .byte 0x41
""", bits=32, arch='intel').hex()) # or just 'intel', 'x86' and so on

# Intel 64-bit
print(assemble("""
  xor r12, r10
  movups [rsp], xmm0
  .word 12345
""", arch='amd64').hex()) # or bits=64/arch='intel' and so on

# ARM 32-bit
print(assemble("""
  mov r1, #0x41
  bl A
A:
  str r1, [r0, r2, LSL#2]
  .asciz "Hello, World!"
  .align 2
""", bits=32, arch='arm').hex())

# ARM 64-bit
print(assemble("""
  mov x1, #0x4141
  bl A
  ldr x0, A
A:
""", arch='aarch64').hex())
