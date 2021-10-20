from math import inf
from random import choice, seed
from typing import Tuple

from ptrlib.algorith.shortestpath import ShortestPath

seed(133333)

ds = [-4, -1, 1, 4]

# 16 puzzle
puzzle = [*range(16)]
goal = tuple(puzzle)
pos = 0

for _ in range(30):
    swappos = pos - choice(ds)
    if 0 <= swappos < 16:
        puzzle[pos], puzzle[swappos] = puzzle[swappos], puzzle[pos]
        pos, swappos = swappos, pos

init = tuple(puzzle)

def transition(state):
    pos = state.index(0)
    for d in ds:
        swappos = pos + d
        if 0 <= swappos < 16:
            l = list(state)
            l[pos], l[swappos] = l[swappos], l[pos]
            yield (tuple(l), 1, (pos, swappos))

def estimator(state):
    cost = 0
    for i in range(len(state)):
        i1, j1 = i // 4, i % 4
        i2, j2 = state[i] // 4, state[i] % 4
        cost += abs(i1 - i2) + abs(j1 - j2)
    return cost // 2

print(f'start: {init}')

sp = ShortestPath(transition, costEstimator=estimator)

cost, path = sp[init][goal]

print(f"cost: {cost}")
print(f"path: {path.value}")
