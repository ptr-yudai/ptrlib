from typing import *
from math import inf

from .base import ShortestPathBase
from .types import *
from .algorithms import *

class ShortestPath(ShortestPathBase, Generic[StateT, EdgeT]):
  def __init__(
    self,
    transition: TransitionFuncT[StateT, EdgeT],
    infinity: NumberT = inf,
    algorithm: Optional[AlgorithmsT] = None,
    costEstimator: Optional[CostEstimatorT[StateT]] = None
  ):
    self.Calculator: ShortestPathBase[StateT, EdgeT]
    
    # select algorithm if not specified
    if algorithm is None:
      if costEstimator is not None:
        algorithm = "astar"
      else:
        algorithm = "dijkstra"
    
    if algorithm == "dijkstra":
      self.Calculator = Dijkstra(transition, infinity)
    if algorithm == "floydwarshall":
      self.Calculator = FloydWarshall(transition, infinity)
    if algorithm == "astar":
      if costEstimator is None: raise ValueError("costEstimator shoud be provided if you want to use A* algorithm")
      self.Calculator = AStar(transition, costEstimator, infinity)

  def __getitem__(self, initState: StateT) -> SupportsGetItem[StateT, ResultT[EdgeT]]:
    return self.Calculator[initState]

__all__ = ["ShortestPath"]
