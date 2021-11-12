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

    def __getitem__(self, init_state: StateT) -> SupportsGetItem[StateT, ResultT[EdgeT]]:
        if init_state not in self.mat:
            init_states_count = len(self.states)
            stack = [init_state]
            while len(stack) != 0:
                state = stack.pop()
                self.states.append(state)
                for nxt_state, cost, edge in self.transition(state):
                    if self.mat[state][nxt_state][0] <= cost:
                        continue
                    self.mat[state][nxt_state] = (cost, LazyList(None, [edge]))
                    if nxt_state not in self.mat:
                        # implicitly create self.mat[nxtState]
                        self.mat[nxt_state]
                        stack.append(nxt_state)
            for i in range(len(self.states)):
                i = self.states[i]
                for j in range(init_states_count, len(self.states)):
                    j = self.states[j]
                    for k in range(init_states_count, len(self.states)):
                        k = self.states[k]
                        new_cost = self.mat[j][i][0] + self.mat[i][k][0]
                        if self.mat[j][k][0] <= new_cost:
                            continue
                        p, q = self.mat[j][i][1], self.mat[i][k][1]
                        assert(p is not None and q is not None)
                        self.mat[j][k] = (new_cost, p + q)
        return self.mat[init_state]


__all__ = ["FloydWarshall"]
