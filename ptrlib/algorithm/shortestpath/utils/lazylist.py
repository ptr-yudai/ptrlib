from __future__ import annotations

import sys
from typing import Generic, TypeVar, Any

sys.setrecursionlimit(max(sys.getrecursionlimit(), 100000))

_T = TypeVar('_T')


class LazyList(Generic[_T]):
    Null: "LazyList[Any]"

    def __init__(self, prev_enumerate: "LazyList[_T] | None", elems: list[_T] | "LazyList[_T]" | None):
        self._prev_enumerate = prev_enumerate
        self._elems = elems

    def __add__(self, other: list[_T] | "LazyList[_T]"):
        return LazyList(self, other)

    def append(self, elem: _T):
        return LazyList(self, [elem])

    @property
    def value(self) -> list[_T]:
        if self._elems is None:
            raise ValueError("list is null")
        if isinstance(self._elems, LazyList):
            self._elems = self._elems.value
        if self._prev_enumerate is None:
            return self._elems[:]
        res = self._prev_enumerate.value
        res.extend(self._elems)
        return res


LazyList.Null = LazyList(None, None)


__all__ = ["LazyList"]
