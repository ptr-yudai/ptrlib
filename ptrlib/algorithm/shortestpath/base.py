from typing import Generic
from abc import ABC, abstractmethod

from .types import *


class ShortestPathBase(ABC, Generic[StateT, EdgeT]):
    @abstractmethod
    def __getitem__(self, init_state: StateT) -> SupportsGetItem[StateT, ResultT[EdgeT]]: ...


__all__ = ["ShortestPathBase"]
