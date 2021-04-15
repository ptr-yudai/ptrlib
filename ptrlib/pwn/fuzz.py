import random

def random_bytes(lmin, lmax=0, charset=None):
    """Generate a random byte array

    Args:
        lmin    (int) : Minimum number of bytes
        lmax    (int) : Maximum number of bytes
        charset (list): List of bytes to be used
    """
    if lmin < 0:
        lmin = 0
    if lmax == 0:
        lmax = lmin
        lmin = 0
    elif lmax < lmin:
        lmin, lmax = lmax, lmin
    if charset == None:
        charset = [i for i in range(0x100)]

    return bytes([random.choice(charset)
                  for i in range(lmin)]) \
        + bytes([random.choice(charset)
                 for i in range(random.randint(0, lmax-lmin))])
