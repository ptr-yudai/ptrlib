Quickstart
==========

Connections
-----------

.. code-block:: python

   from ptrlib import Process, Socket, SSH

   io = Process("./pwn01")
   io = Socket("localhost", 1234)
   io = SSH("example.com", username="ubuntu", password="p4s$w0rd")

ELF parsing
-----------

.. code-block:: python

   from ptrlib import ELF

   elf = ELF("./pwn01")
   libc = ELF("./libc.so.6")

CPU helpers
-----------

.. code-block:: python

   from ptrlib import CPU, ArmCPU

   arm = ArmCPU(32)
   code = arm.assemble("mov r0, #1; mov r1, #2")

   x64 = CPU("intel", 64)
   insns = x64.disassemble(b"\x64\x89\xd0\x90")
   print(insns[0].mnemonic)

