from ptrlib import *

text = "The quick brown fox jumps over the lazy dog."
print(chunks(text, 8))
print(chunks(text, 8, True))

data = [1, 2, 3, 4, 5, 6, 7, 8]
print(chunks(data, 3))
print(chunks(data, 3, True))
