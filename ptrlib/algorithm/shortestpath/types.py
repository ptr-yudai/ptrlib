from typing import *

from .utils.lazylist import LazyList

_KT_contra = TypeVar("_KT_contra", contravariant=True)
_VT_co = TypeVar("_VT_co", covariant=True)
class SupportsGetItem(Container[_KT_contra], Protocol[_KT_contra, _VT_co]):
    def __getitem__(self, __k: _KT_contra) -> _VT_co: ...

StateT = TypeVar('StateT')
EdgeT = TypeVar('EdgeT')
NumberT = Union[int, float]
AlgorithmsT = Literal["dijkstra", "floydwarshall", "astar"]

ResultT = Tuple[NumberT, LazyList[EdgeT]]
TransitionFuncT = Callable[[StateT], Iterator[Tuple[StateT, NumberT, EdgeT]]]
CostEstimatorT = Callable[[StateT, StateT], NumberT]

__all__ = ["SupportsGetItem", "StateT", "EdgeT", "NumberT", "ResultT", "TransitionFuncT", "CostEstimatorT", "AlgorithmsT"]
