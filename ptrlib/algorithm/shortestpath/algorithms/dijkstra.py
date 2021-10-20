from collections import defaultdict
import heapq
from math import inf
from typing import *

from ..types import *
from ..base import ShortestPathBase
from ..utils.lazylist import LazyList

StateT_Inner = TypeVar('StateT_Inner')
EdgeT_Inner = TypeVar('EdgeT_Inner')


class Dijkstra(ShortestPathBase[StateT, EdgeT]):
    class _Dijkstra_Container(Generic[StateT_Inner, EdgeT_Inner]):
        def __init__(self, transition: TransitionFuncT[StateT_Inner, EdgeT_Inner], infinity: NumberT, initState: StateT_Inner) -> None:
            self.transition = transition
            self.infinity = infinity
            self.res: DefaultDict[StateT_Inner, ResultT[EdgeT_Inner]] = defaultdict(
                lambda: (self.infinity, LazyList.Null))
            self.reached: Set[StateT_Inner] = set()
            self.res[initState] = (0, LazyList(None, []))
            self.heap: List[Tuple[NumberT, StateT_Inner]] = [(0, initState)]

        def __getitem__(self, destState: StateT_Inner) -> ResultT[EdgeT_Inner]:
            while len(self.heap) != 0 and destState not in self.reached:
                _, elem = heapq.heappop(self.heap)
                if elem in self.reached:
                    continue
                self.reached.add(elem)
                cost, path = self.res[elem]
                assert(path is not None)
                for (next, d, edge) in self.transition(elem):
                    nextCost = cost + d
                    if (next in self.res) and (self.res[next][0] <= nextCost):
                        continue
                    self.res[next] = (nextCost, path.append(edge))
                    heapq.heappush(self.heap, (nextCost, next))
            return self.res[destState]

    def __init__(
        self,
        transition: TransitionFuncT[StateT, EdgeT],
        infinity: NumberT = inf
    ):
        self.transition = transition
        self.memo: Dict[StateT,
                        Dijkstra._Dijkstra_Container[StateT, EdgeT]] = dict()
        self.infinity: NumberT = infinity

    def __getitem__(self, initState: StateT) -> _Dijkstra_Container[StateT, EdgeT]:
        if initState not in self.memo:
            self.memo[initState] = Dijkstra._Dijkstra_Container(
                self.transition, self.infinity, initState)
        return self.memo[initState]


__all__ = ["Dijkstra"]
