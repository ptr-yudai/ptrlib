"""This package provides a type representing a generator or an integer.
"""
from typing import Generator
from ptrlib.types import PtrlibIntLikeT


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
        self._cache = []
        self._cursor = 0

    def __getitem__(self, index: PtrlibIntLikeT) -> int:
        """Get n-th value of the generator
        """
        index = int(index)

        if index >= len(self._cache):
            for _ in range(index + 1- len(self._cache)):
                self._cache.append(next(self._generator))

        return self._cache[index]

    def __int__(self) -> int:
        """Get the first value of the generator
        """
        return self[0]

    def __index__(self) -> int:
        """Get the first value of the generator
        """
        return int(self)

    def __iter__(self) -> 'GeneratorOrInt':
        return self

    def __next__(self) -> int:
        """Get next value
        """
        self._cursor += 1

        if self._cursor - 1 < len(self._cache):
            return self._cache[self._cursor - 1]

        self._cache.append(next(self._generator))
        return self._cache[-1]

    def __eq__(self, other) -> bool:
        if isinstance(other, GeneratorOrInt):
            return self._generator == other._generator

        if isinstance(other, int):
            return self[0] == other

        raise NotImplementedError(f"'==' not supported between instances of "
                                  f"'{type(self)}' and '{type(other)}'")

    def __lt__(self, other) -> bool:
        if isinstance(other, int):
            return self[0] < other

        raise NotImplementedError(f"'<' not supported between instances of "
                                  f"'{type(self)}' and '{type(other)}'")

    def __str__(self) -> str:
        if len(self._cache) <= 1:
            return f'GeneratorOrInt({repr(self._symbol)} @ {hex(self[0])})'
        return f'GeneratorOrInt({repr(self._symbol)} @ {hex(self._cache[0])} ' \
                f'and {len(self._cache) - 1} more known values)'


__all__ = ['GeneratorOrInt']
