import unittest
from math import inf
from random import random, seed, randrange
from logging import getLogger, FATAL
from ptrlib.algorithm.shortestpath import *

NODE_COUNT = 100
PATH_PROB = 0.5
EDGE_WEIGHT_MIN = 1
EDGE_WEIGHT_MAX = 100
SEED = 1337
ALGORITHMS = ["dijkstra", "floydwarshall"]


class TestShortestPath(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        seed(SEED)
        self.nodes = [*range(NODE_COUNT)]
        self.graph = [[inf for j in range(NODE_COUNT)]
                      for i in range(NODE_COUNT)]
        for i in range(NODE_COUNT):
            for j in range(NODE_COUNT):
                if i == j:
                    self.graph[i][j] = 0
                elif random() < PATH_PROB:
                    self.graph[i][j] = randrange(
                        EDGE_WEIGHT_MIN, EDGE_WEIGHT_MAX)
        self.ans = [[*l] for l in self.graph]
        for i in range(NODE_COUNT):
            for j in range(NODE_COUNT):
                for k in range(NODE_COUNT):
                    self.ans[j][k] = min(
                        self.ans[j][k], self.ans[j][i] + self.ans[i][k])

    def test_shortestpath(self):
        def test_algorithm(algo, expectClass):
            def transition(state):
                for nxt in range(NODE_COUNT):
                    if self.graph[state][nxt] == inf:
                        continue
                    yield (nxt, self.graph[state][nxt], (state, nxt))
            sp = ShortestPath(transition, algorithm=algo)
            self.assertIsInstance(sp.calculator, expectClass)
            for i in range(NODE_COUNT):
                for j in range(NODE_COUNT):
                    cost, route = sp[i][j]
                    self.assertEqual(
                        cost, self.ans[i][j], f'{i}, {j}, {cost}, {self.ans[i][j]}')
                    if self.ans[i][j] == inf:
                        with self.assertRaises(ValueError):
                            route.value
                        continue
                    self.assertIsNotNone(route)
                    prev = i
                    for s, t in route.value:
                        self.assertEqual(prev, s)
                        prev = t
                    self.assertEqual(prev, j)
        test_algorithm("dijkstra", Dijkstra)
        test_algorithm("floydwarshall", FloydWarshall)

    def test_astar(self):
        def transition(state):
            for nxt in range(NODE_COUNT):
                if self.graph[state][nxt] == inf:
                    continue
                yield (nxt, self.graph[state][nxt], (state, nxt))

        def estimator(state, goal):
            return self.ans[state][goal]

        with self.assertRaises(ValueError):
            ShortestPath(transition, algorithm="astar")

        sp = ShortestPath(transition, cost_estimator=estimator)
        self.assertIsInstance(sp.calculator, AStar)
        for goal in range(NODE_COUNT):
            cost, route = sp[0][goal]
            self.assertEqual(cost, self.ans[0][goal])
            if self.ans[0][goal] == inf:
                with self.assertRaises(ValueError):
                    route.value
                return
            self.assertIsNotNone(route)
            prev = 0
            for s, t in route.value:
                self.assertEqual(prev, s)
                prev = t
            self.assertEqual(prev, goal)
