from collections import defaultdict
from typing import TypeVar, Generic
import heapq
from math import inf

from ..utils.lazylist import LazyList
from ..base import ShortestPathBase
from ..types import CostEstimatorT, StateT, EdgeT, NumberT, ResultT, TransitionFuncT

StateT_Inner = TypeVar('StateT_Inner')
EdgeT_Inner = TypeVar('EdgeT_Inner')


class AStar(ShortestPathBase[StateT, EdgeT]):
    memo: dict[StateT, "AStar._AStar_Container[StateT, EdgeT]"]

    class _AStar_Container(Generic[StateT_Inner, EdgeT_Inner]):
        res: defaultdict[StateT_Inner, ResultT[EdgeT_Inner]]

        def __init__(
            self,
            transition: TransitionFuncT[StateT_Inner, EdgeT_Inner],
            cost_estimator: CostEstimatorT[StateT_Inner],
            infinity: NumberT,
            init_state: StateT_Inner
        ) -> None:
            self.transition = transition
            self.cost_estimator = cost_estimator
            self.infinity = infinity
            self.res = defaultdict(lambda: (self.infinity, LazyList.Null))
            self.res[init_state] = (0, LazyList(None, []))

        def __getitem__(self, dest_state: StateT_Inner) -> ResultT[EdgeT_Inner]:
            arrived: dict[StateT_Inner, bool] = dict()
            fixed: set[StateT_Inner] = set()
            cur_res = defaultdict(lambda: (self.infinity, LazyList.Null))
            heap: list[tuple[float, float, StateT_Inner]] = []

            for state in self.res.keys():
                cost, path = self.res[state]
                arrived[state] = False
                fixed.add(state)
                cur_res[state] = (cost, path)
                heap.append((cost + self.cost_estimator(state, dest_state), cost, state))
            heapq.heapify(heap)

            while len(heap) != 0 and dest_state not in fixed:
                _, cost, state = heapq.heappop(heap)
                if arrived[state]:
                    continue
                if state == dest_state:
                    fixed.add(state)
                arrived[state] = True
                cost, path = cur_res[state]
                assert(path is not None)
                for (next, d, edge) in self.transition(state):
                    next_cost = cost + d
                    if (next in cur_res) and (cur_res[next][0] <= next_cost):
                        continue
                    arrived[next] = False
                    cur_res[next] = (next_cost, path.append(edge))
                    heapq.heappush(heap, (next_cost + self.cost_estimator(next, dest_state), next_cost, next))
            self.res[dest_state] = cur_res[dest_state]
            return self.res[dest_state]

    def __init__(
        self,
        transition: TransitionFuncT[StateT, EdgeT],
        cost_estimator: CostEstimatorT[StateT],
        infinity: NumberT = inf
    ) -> None:
        self.transition = transition
        self.cost_estimator = cost_estimator
        self.memo = dict()
        self.infinity: NumberT = infinity

    def __getitem__(self, initState: StateT) -> _AStar_Container[StateT, EdgeT]:
        if initState not in self.memo:
            self.memo[initState] = AStar._AStar_Container(
                self.transition, self.cost_estimator, self.infinity, initState)
        return self.memo[initState]


__all__ = ["AStar"]
