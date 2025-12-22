from collections.abc import Callable, Iterator
from typing import Generic, TypeVar, Protocol, Literal, TypeAlias

from .utils.lazylist import LazyList


_KT_contra = TypeVar("_KT_contra", contravariant=True)
_VT_co = TypeVar("_VT_co", covariant=True)
class SupportsGetItem(Protocol, Generic[_KT_contra, _VT_co]):
    def __getitem__(self, __k: _KT_contra) -> _VT_co: ...

StateT = TypeVar('StateT')
EdgeT = TypeVar('EdgeT')
NumberT: TypeAlias = int | float
AlgorithmsT: TypeAlias = Literal["dijkstra", "floydwarshall", "astar"]

ResultT: TypeAlias = tuple[NumberT, LazyList[EdgeT]]
TransitionFuncT: TypeAlias = Callable[[StateT], Iterator[tuple[StateT, NumberT, EdgeT]]]
CostEstimatorT: TypeAlias = Callable[[StateT, StateT], NumberT]


__all__ = ["SupportsGetItem", "StateT", "EdgeT", "NumberT", "ResultT", "TransitionFuncT", "CostEstimatorT", "AlgorithmsT"]
