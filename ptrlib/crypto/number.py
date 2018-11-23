"""Number theory"""
def gcd(a, b):
    """Get the greatest common divisor of a, b"""
    if a < b:
        a, b = b, a
    if b == 0:
        return a
    return gcd(b, a % b)

def lcm(a, b):
    """Get the least common multiple of a, b"""
    return (a * b) // gcd(a, b)

def ceil_sqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n//x) // 2
    return x

def is_square(n):
    """Check whether n is a square number"""
    x = ceil_sqrt(n)
    return x*x == n
