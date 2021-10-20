import sys
from typing import *

sys.setrecursionlimit(max(sys.getrecursionlimit(), 100000))

_T = TypeVar('_T')


class LazyList(Generic[_T]):
    Null: "LazyList"

    def __init__(self, prevEnumerate: "Optional[LazyList[_T]]", elems: Optional[Union[List[_T], "LazyList[_T]"]]):
        self._prevEnumerate = prevEnumerate
        self._elems = elems

    def __add__(self, other: Union[List[_T], "LazyList[_T]"]):
        return LazyList(self, other)

    def append(self, elem: _T):
        return LazyList(self, [elem])

    @property
    def value(self) -> List[_T]:
        if self._elems is None:
            raise ValueError("list is null")
        if isinstance(self._elems, LazyList):
            self._elems = self._elems.value
        if self._prevEnumerate is None:
            return self._elems[:]
        res = self._prevEnumerate.value
        res.extend(self._elems)
        return res


LazyList.Null = LazyList(None, None)

__all__ = ["LazyList"]
