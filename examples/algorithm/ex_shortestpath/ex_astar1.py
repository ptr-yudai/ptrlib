from math import inf
from random import randrange
import string

from ptrlib.algorithm.shortestpath import ShortestPath

res = str(randrange(0, 1 << 64))

def transition(state: str):
    for d in string.digits:
        yield (state + d, 1, d)
    if len(state) != 0: yield (state[:-1], 1, "DEL")

def estimator(state: str, goal: str):
    cost = len(goal) - len(state) if res.startswith(state) else inf
    return cost

sp = ShortestPath(transition, cost_estimator=estimator)

cost, path = sp[""][res]

print(f"cost: {cost}")
print(f"path: {path.value}")
