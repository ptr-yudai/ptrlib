Installation
============

Requirements
------------

* Python 3.10 or later
* Runtime dependencies:

  * ``pycryptodome``
  * ``pywin32`` (Windows only)

Install from PyPI
-----------------

.. code-block:: bash

   python -m pip install --upgrade ptrlib

Install from source (this repository)
-------------------------------------

.. code-block:: bash

   git clone https://github.com/ptr-yudai/ptrlib.git
   cd ptrlib
   python -m pip install -U pip
   python -m pip install -e .

Optional external tools
-----------------------

Some features require external programs or optional libraries.

* SSH features require an ``ssh`` client.
* Intel assembler/disassembler features can use tools such as ``gcc``, ``objcopy``, ``nasm``, ``objdump``,
  or optional Python libraries like ``keystone-engine`` / ``capstone``.
* ARM/MIPS CPU helpers may require cross-toolchains.

