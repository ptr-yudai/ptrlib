from ptrlib.algorith.shortestpath import ShortestPath

X = 20
Y = 120

cost_a = 2
cost_b = 8
n = 256

def transition(state):
  for i in range(6):
    yield ((state + i) % n, cost_a, f"A{i}")
    yield ((state + state + i) % n, cost_b, f"B{i}") 

sp = ShortestPath(transition)

(cost, path) = sp[X][Y]
print(f'cost: {cost}')
print(f'path: {path.value}')