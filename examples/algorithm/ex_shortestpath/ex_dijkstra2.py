from random import random, randrange, seed
from math import inf

from ptrlib.algorithm.shortestpath import ShortestPath

seed(1337)

NODE_COUNT = 100
PATH_PROB = 0.5
EDGE_WEIGHT_MIN = 1
EDGE_WEIGHT_MAX = 100

n = 100
nodes = [*range(NODE_COUNT)]
graph = [[0 if i == j else inf if PATH_PROB < random() else randrange(EDGE_WEIGHT_MIN, EDGE_WEIGHT_MAX) for j in range(NODE_COUNT)] for i in range(NODE_COUNT)]

def transition(state: int):
    for nxt in range(NODE_COUNT):
        if graph[state][nxt] == inf: continue
        yield (nxt, graph[state][nxt], (state, nxt))

sp = ShortestPath(transition)

cost, path = sp[0][NODE_COUNT - 1]

print(f"cost: {cost}")
print(f"path: {path.value if cost != inf else None}")
