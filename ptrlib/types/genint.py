"""This package provides a type representing a generator or an integer.
"""
from typing import Generator


class GeneratorOrInt:
    """A class representing a gadget.

    This class instance can be treated as a generator with `next`,
    or converted into the first element integer with `int`.

    Examples:
        ```
        g = elf.gadget("pop rdi; ret;")
        print(next(g)) # 0x4012ac
        print(next(g)) # 0x40135f
        print(int(g))  # 0x4012ac
        ```
    """
    def __init__(self, generator: Generator[int, None, None], symbol: bytes=b''):
        self._generator = generator
        self._symbol = symbol
        self._first = None

    @property
    def generator(self) -> Generator[int, None, None]:
        """Get generator
        """
        return self._generator

    def __int__(self) -> int:
        if self._first is None:
            v = next(self._generator)
            self._first = v
            return v
        return self._first

    def __iter__(self) -> 'GeneratorOrInt':
        return self

    def __next__(self) -> int:
        v = next(self._generator)
        if self._first is None:
            self._first = v
        return v

    def __str__(self) -> str:
        if self._first is None:
            return f'GeneratorOrInt({repr(self._symbol)})'
        return f'GeneratorOrInt({repr(self._symbol)} @ {hex(self._first)})'


__all__ = ['GeneratorOrInt']
