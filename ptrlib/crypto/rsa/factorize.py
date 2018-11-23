"""Factoring algorithms"""
from ..prime import *
from ..number import *
import math

def factorize_fermat(n):
    a = ceil_sqrt(n)
    b2 = a*a - n
    while not is_square(b2):
        a += 1
        b2 = a*a - n
    p = a - ceil_sqrt(b2)
    return p, n / p

def factorize_pollards_rho(n):
    """Factoring by Pollard's rho algorithm"""
    if is_prime(n):
        return (n, 1)
    x, y, d = 2, 2, 1
    while d == 1:
        x = (x * x + 1) % n
        y = (y * y + 1) % n
        y = (y * y + 1) % n
        d = gcd(abs(x - y), n)
    return (d, n / d)

