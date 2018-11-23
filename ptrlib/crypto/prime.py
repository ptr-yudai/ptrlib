"""Prime-related functions"""
import random

def is_prime(n, k=50):
    """Miller Rabin primary test

    This method probabilistically determines whether a given number is prime.
    It returns True when n is prime, otherwise False.
    With a probability 4^(-k), it returns True even though n is a composite number.
    There is no possibility that it returns False even though n is a prime number.
    """
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    # n = 1 + s * 2^r
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in xrange(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in xrange(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def new_prime(n, k=50):
    """Create a new prime of n bits

    This method creates a prime number of n bits.
    """
    max_number = 1 << n
    mask_number = max_number >> 1
    while True:
        x = random.randint(2, max_number)
        x |= mask_number
        if is_prime(x, k):
            break
    return x
