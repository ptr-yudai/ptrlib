#!/usr/bin/env python
from ptrlib import *

for password in brute_force_attack(4):
    print(brute_force_pattern(password))
