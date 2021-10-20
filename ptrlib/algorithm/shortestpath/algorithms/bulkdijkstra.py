from collections import defaultdict
from typing import *
import heapq
from math import inf

from ..utils.lazylist import LazyList
from ..base import ShortestPathBase
from ..types import StateT, EdgeT, NumberT, ResultT, DefaultDict, TransitionFuncT

class BulkDijkstra(ShortestPathBase[StateT, EdgeT]):
  def __init__(
    self,
    transition: TransitionFuncT[StateT, EdgeT],
    infinity: NumberT=inf
  ) -> None:
    self.transition = transition
    self.memo: Dict[StateT, DefaultDict[StateT, ResultT[EdgeT]]] = dict()
    self.infinity: NumberT = infinity
  def __getitem__(self, initState: StateT) -> Dict[StateT, ResultT[EdgeT]]:
    if initState not in self.memo:
      res: DefaultDict[StateT, ResultT[EdgeT]] = defaultdict(lambda: (self.infinity, None))
      reached: Set[StateT] = set()
      res[initState] = (0, LazyList(None, []))
      heap: List[Tuple[NumberT, StateT]] = [(0, initState)]
      while len(heap) != 0:
        _, elem = heapq.heappop(heap)
        if elem in reached: continue
        reached.add(elem)
        cost, path = res[elem]
        assert(path is not None)
        for (next, d, edge) in self.transition(elem):
          nextCost = cost + d
          if (next in res) and (res[next][0] <= nextCost): continue
          res[next] = (nextCost, path.append(edge))
          heapq.heappush(heap, (nextCost, next))
      self.memo[initState] = res
    return self.memo[initState]

__all__ = ["BulkDijkstra"]
