from typing import Generic
from abc import ABC, abstractmethod

from .types import EdgeT, ResultT, StateT, SupportsGetItem


class ShortestPathBase(ABC, Generic[StateT, EdgeT]):
    """Base class for ShortestPath
    """
    @abstractmethod
    def __getitem__(self, init_state: StateT) -> SupportsGetItem[StateT, ResultT[EdgeT]]: ...


__all__ = ["ShortestPathBase"]
