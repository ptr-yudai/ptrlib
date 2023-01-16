from typing import Generic, Union, TypeVar, Tuple, Callable, Iterator

try:
    from typing import Protocol
except:
    from typing_extensions import Protocol
try:
    from typing import Literal
except:
    from typing_extensions import Literal

from .utils.lazylist import LazyList

_KT_contra = TypeVar("_KT_contra", contravariant=True)
_VT_co = TypeVar("_VT_co", covariant=True)
class SupportsGetItem(Protocol, Generic[_KT_contra, _VT_co]):
    def __getitem__(self, __k: _KT_contra) -> _VT_co: ...

StateT = TypeVar('StateT')
EdgeT = TypeVar('EdgeT')
NumberT = Union[int, float]
AlgorithmsT = Literal["dijkstra", "floydwarshall", "astar"]

ResultT = Tuple[NumberT, LazyList[EdgeT]]
TransitionFuncT = Callable[[StateT], Iterator[Tuple[StateT, NumberT, EdgeT]]]
CostEstimatorT = Callable[[StateT, StateT], NumberT]

__all__ = ["SupportsGetItem", "StateT", "EdgeT", "NumberT", "ResultT", "TransitionFuncT", "CostEstimatorT", "AlgorithmsT"]
