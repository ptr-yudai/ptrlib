#!/usr/bin/env python
from ptrlib import bruteforce

for password in bruteforce(1, 3, charset='012'):
    print(password)
