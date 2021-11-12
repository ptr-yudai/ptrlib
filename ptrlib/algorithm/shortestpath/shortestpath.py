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
        cost_estimator: Optional[CostEstimatorT[StateT]] = None
    ):
        self.calculator: ShortestPathBase[StateT, EdgeT]

        # select algorithm if not specified
        if algorithm is None:
            if cost_estimator is not None:
                algorithm = "astar"
            else:
                algorithm = "dijkstra"

        if algorithm == "dijkstra":
            self.calculator = Dijkstra(transition, infinity)
        if algorithm == "floydwarshall":
            self.calculator = FloydWarshall(transition, infinity)
        if algorithm == "astar":
            if cost_estimator is None:
                raise ValueError(
                    "costEstimator shoud be provided if you want to use A* algorithm")
            self.calculator = AStar(transition, cost_estimator, infinity)

    def __getitem__(self, init_state: StateT) -> SupportsGetItem[StateT, ResultT[EdgeT]]:
        return self.calculator[init_state]


__all__ = ["ShortestPath"]
