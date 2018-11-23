#!/usr/bin/env python
from ptrlib import *

# Generate a new prime
print("1024 bit prime:")
print(new_prime(1024))

# Check primality
print("Enter a number to check primality.")
x = int(raw_input(">> "))
if is_prime(x):
    print("It is a prime number.")
else:
    print("It is a composite number.")
