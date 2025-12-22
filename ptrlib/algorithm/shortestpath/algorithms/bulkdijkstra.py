from collections import defaultdict
import heapq
from math import inf

from ..utils.lazylist import LazyList
from ..base import ShortestPathBase
from ..types import StateT, EdgeT, NumberT, ResultT, TransitionFuncT


class BulkDijkstra(ShortestPathBase[StateT, EdgeT]):
    memo: dict[StateT, defaultdict[StateT, ResultT[EdgeT]]]

    def __init__(
        self,
        transition: TransitionFuncT[StateT, EdgeT],
        infinity: NumberT = inf
    ) -> None:
        self.transition = transition
        self.memo = dict()
        self.infinity: NumberT = infinity

    def __getitem__(self, init_state: StateT) -> dict[StateT, ResultT[EdgeT]]:
        if init_state not in self.memo:
            res: defaultdict[StateT, ResultT[EdgeT]] = defaultdict(
                lambda: (self.infinity, LazyList.Null))
            reached: set[StateT] = set()
            res[init_state] = (0, LazyList(None, []))
            heap: list[tuple[float, StateT]] = [(0, init_state)]
            while len(heap) != 0:
                _, elem = heapq.heappop(heap)
                if elem in reached:
                    continue
                reached.add(elem)
                cost, path = res[elem]
                assert(path is not None)
                for (next, d, edge) in self.transition(elem):
                    next_cost = cost + d
                    if (next in res) and (res[next][0] <= next_cost):
                        continue
                    res[next] = (next_cost, path.append(edge))
                    heapq.heappush(heap, (next_cost, next))
            self.memo[init_state] = res
        return self.memo[init_state]


__all__ = ["BulkDijkstra"]
