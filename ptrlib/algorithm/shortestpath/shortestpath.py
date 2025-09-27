"""This package defines a shortest path problem solver.
"""
from math import inf
from typing import Optional, Generic

from .algorithms import *
from .base import ShortestPathBase
from .types import *


class ShortestPath(ShortestPathBase[StateT, EdgeT], Generic[StateT, EdgeT]):
    """Solver for the shortest path problem.
    """
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
