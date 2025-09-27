"""This package provides a type representing a generator or an integer.
"""
from typing import Generator
from ptrlib.types import PtrlibIntLikeT


class GeneratorOrInt(object):
    """A class representing a gadget.

    This class instance can be treated as a generator with `next`,
    or converted into the first element integer with `int`.

    Examples:
        ```
        g = elf.gadget("pop rdi; ret;")
        x = GeneratorOrInt(g, b"pop rdi; ret;")
        print(next(x)) # 0x4012ac
        print(next(x)) # 0x40135f
        print(int(x))  # 0x4012ac

        # int-like ops
        print(x + 4)        # OK
        print(4 + x)        # OK (reflected)
        print(x >> 8)       # OK
        print(x & 0xfff)    # OK
        ```
    """
    def __init__(self, generator: Generator[int, None, None], symbol: bytes = b''):
        self._generator = generator
        self._symbol = symbol
        self._cache = []
        self._cursor = 0

    def _as_int(self) -> int:
        return self[0]

    def __getitem__(self, index: PtrlibIntLikeT) -> int:
        """Get n-th value of the generator (0-based)."""
        index = int(index)
        if index < 0:
            raise IndexError("negative indices are not supported")

        if index >= len(self._cache):
            for _ in range(index + 1 - len(self._cache)):
                self._cache.append(next(self._generator))
        return self._cache[index]

    def __int__(self) -> int:
        """Get the first value of the generator."""
        return self[0]

    def __index__(self) -> int:
        """Allow usage where an 'index integer' is required (e.g., slicing)."""
        return int(self)

    def __iter__(self) -> 'GeneratorOrInt':
        return self

    def __next__(self) -> int:
        """Get next value."""
        self._cursor += 1
        if self._cursor - 1 < len(self._cache):
            return self._cache[self._cursor - 1]
        self._cache.append(next(self._generator))
        return self._cache[-1]

    def _coerce_other(self, other):
        if isinstance(other, GeneratorOrInt):
            return int(other)
        return int(other)

    def __eq__(self, other) -> bool:
        try:
            return self._as_int() == self._coerce_other(other)
        except Exception:
            return NotImplemented

    def __ne__(self, other) -> bool:
        try:
            return self._as_int() != self._coerce_other(other)
        except Exception:
            return NotImplemented

    def __lt__(self, other) -> bool:
        try:
            return self._as_int() < self._coerce_other(other)
        except Exception:
            return NotImplemented

    def __le__(self, other) -> bool:
        try:
            return self._as_int() <= self._coerce_other(other)
        except Exception:
            return NotImplemented

    def __gt__(self, other) -> bool:
        try:
            return self._as_int() > self._coerce_other(other)
        except Exception:
            return NotImplemented

    def __ge__(self, other) -> bool:
        try:
            return self._as_int() >= self._coerce_other(other)
        except Exception:
            return NotImplemented

    def __bool__(self) -> bool:
        return bool(self._as_int())

    def __neg__(self): return -self._as_int()
    def __pos__(self): return +self._as_int()
    def __abs__(self): return abs(self._as_int())
    def __invert__(self): return ~self._as_int()

    def __add__(self, other): return self._as_int() + self._coerce_other(other)
    def __sub__(self, other): return self._as_int() - self._coerce_other(other)
    def __mul__(self, other): return self._as_int() * self._coerce_other(other)
    def __floordiv__(self, other): return self._as_int() // self._coerce_other(other)
    def __truediv__(self, other): return self._as_int() / self._coerce_other(other)
    def __mod__(self, other): return self._as_int() % self._coerce_other(other)
    def __pow__(self, other, modulo=None):
        if modulo is None:
            return pow(self._as_int(), self._coerce_other(other))
        return pow(self._as_int(), self._coerce_other(other), int(modulo))

    def __radd__(self, other): return self._coerce_other(other) + self._as_int()
    def __rsub__(self, other): return self._coerce_other(other) - self._as_int()
    def __rmul__(self, other): return self._coerce_other(other) * self._as_int()
    def __rfloordiv__(self, other): return self._coerce_other(other) // self._as_int()
    def __rtruediv__(self, other): return self._coerce_other(other) / self._as_int()
    def __rmod__(self, other): return self._coerce_other(other) % self._as_int()
    def __rpow__(self, other): return pow(self._coerce_other(other), self._as_int())

    def __and__(self, other): return self._as_int() & self._coerce_other(other)
    def __or__(self, other): return self._as_int() | self._coerce_other(other)
    def __xor__(self, other): return self._as_int() ^ self._coerce_other(other)
    def __lshift__(self, other): return self._as_int() << self._coerce_other(other)
    def __rshift__(self, other): return self._as_int() >> self._coerce_other(other)

    def __rand__(self, other): return self._coerce_other(other) & self._as_int()
    def __ror__(self, other): return self._coerce_other(other) | self._as_int()
    def __rxor__(self, other): return self._coerce_other(other) ^ self._as_int()
    def __rlshift__(self, other): return self._coerce_other(other) << self._as_int()
    def __rrshift__(self, other): return self._coerce_other(other) >> self._as_int()

    def __str__(self) -> str:
        if len(self._cache) <= 1:
            return f'GeneratorOrInt({repr(self._symbol)} @ {hex(self[0])})'
        return (f'GeneratorOrInt({repr(self._symbol)} @ {hex(self._cache[0])} '
                f'and {len(self._cache) - 1} more known values)')

    def __repr__(self) -> str:
        if not self._cache:
            return f'{self.__class__.__name__}(uninitialized)'
        return (f"{self.__class__.__name__}(first={hex(self._cache[0])}, "
                f"known={len(self._cache)}, symbol={self._symbol!r})")


__all__ = ['GeneratorOrInt']
