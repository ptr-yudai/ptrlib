from collections import defaultdict
from typing import *
import heapq
from math import inf

from ..utils.lazylist import LazyList
from ..base import ShortestPathBase
from ..types import CostEstimatorT, StateT, EdgeT, NumberT, ResultT, DefaultDict, TransitionFuncT

StateT_Inner = TypeVar('StateT_Inner')
EdgeT_Inner = TypeVar('EdgeT_Inner')
class AStar(ShortestPathBase[StateT, EdgeT]):
  class _AStar_Container(Generic[StateT_Inner, EdgeT_Inner]):
    def __init__(
      self,
      transition: TransitionFuncT[StateT_Inner, EdgeT_Inner],
      costEstimator: CostEstimatorT[StateT_Inner],
      infinity: NumberT,
      initState: StateT_Inner
    ) -> None:
      self.transition = transition
      self.costEstimator = costEstimator
      self.infinity = infinity
      self.res: DefaultDict[StateT_Inner, ResultT[EdgeT_Inner]] = defaultdict(lambda: (self.infinity, LazyList.Null))
      self.arrived: Dict[StateT_Inner, bool] = dict()
      self.estimatorCache: Dict[StateT_Inner, NumberT] = dict()
      self.fixed: Set[StateT_Inner] = set()
      self.heap: List[Tuple[NumberT, NumberT, StateT_Inner]] = [(self._getEstimatedCost(initState), 0, initState)]

      self.res[initState] = (0, LazyList(None, []))
      self.arrived[initState] = False

    def _getEstimatedCost(self, state: StateT_Inner) -> NumberT:
      if state not in self.estimatorCache:
        self.estimatorCache[state] = self.costEstimator(state)
        if self.estimatorCache[state] < 0:
          raise ValueError("Estimated cost should not be lower than zero.")
      return self.estimatorCache[state]

    def __getitem__(self, destState: StateT_Inner) -> ResultT[EdgeT_Inner]:
      assert(self._getEstimatedCost(destState) == 0)
      while len(self.heap) != 0 and destState not in self.fixed:
        _, cost, state = heapq.heappop(self.heap)
        if self.arrived[state]: continue
        if state == destState: self.fixed.add(state)
        self.arrived[state] = True
        cost, path = self.res[state]
        assert(path is not None)
        for (next, d, edge) in self.transition(state):
          nextCost = cost + d
          if (next in self.res) and (self.res[next][0] <= nextCost): continue
          self.arrived[next] = False
          self.res[next] = (nextCost, path.append(edge))
          heapq.heappush(self.heap, (nextCost + self._getEstimatedCost(next), nextCost, next))
      return self.res[destState] 

  def __init__(
      self,
      transition: TransitionFuncT[StateT, EdgeT],
      costEstimator: CostEstimatorT[StateT],
      infinity: NumberT=inf
    ) -> None:
      self.transition = transition
      self.costEstimator = costEstimator
      self.memo: Dict[StateT, AStar._AStar_Container[StateT, EdgeT]] = dict()
      self.infinity: NumberT = infinity
    
  def __getitem__(self, initState: StateT) -> _AStar_Container[StateT, EdgeT]:
    if initState not in self.memo:
      self.memo[initState] = AStar._AStar_Container(self.transition, self.costEstimator, self.infinity, initState)
    return self.memo[initState]

__all__ = ["AStar"]
