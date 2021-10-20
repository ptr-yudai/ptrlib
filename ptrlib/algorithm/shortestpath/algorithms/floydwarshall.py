from collections import defaultdict
from math import inf
from typing import *

from ..types import *
from ..base import ShortestPathBase
from ..utils.lazylist import LazyList


class FloydWarshall(ShortestPathBase[StateT, EdgeT]):
    def __init__(
        self,
        transition: TransitionFuncT[StateT, EdgeT],
        infinity: NumberT = inf
    ) -> None:
        self.transition = transition
        self.infinity = infinity
        self.mat: DefaultDict[StateT, DefaultDict[StateT, ResultT[EdgeT]]] = defaultdict(
            lambda: defaultdict(lambda: (self.infinity, LazyList.Null)))
        self.states: List[StateT] = []

    def __getitem__(self, initState: StateT) -> SupportsGetItem[StateT, ResultT[EdgeT]]:
        if initState not in self.mat:
            initStatesCount = len(self.states)
            stack = [initState]
            while len(stack) != 0:
                state = stack.pop()
                self.states.append(state)
                for nxtState, cost, edge in self.transition(state):
                    if self.mat[state][nxtState][0] <= cost:
                        continue
                    self.mat[state][nxtState] = (cost, LazyList(None, [edge]))
                    if nxtState not in self.mat:
                        # implicitly create self.mat[nxtState]
                        self.mat[nxtState]
                        stack.append(nxtState)
            for i in range(len(self.states)):
                i = self.states[i]
                for j in range(initStatesCount, len(self.states)):
                    j = self.states[j]
                    for k in range(initStatesCount, len(self.states)):
                        k = self.states[k]
                        newCost = self.mat[j][i][0] + self.mat[i][k][0]
                        if self.mat[j][k][0] <= newCost:
                            continue
                        p, q = self.mat[j][i][1], self.mat[i][k][1]
                        assert(p is not None and q is not None)
                        self.mat[j][k] = (newCost, p + q)
        return self.mat[initState]


__all__ = ["FloydWarshall"]
