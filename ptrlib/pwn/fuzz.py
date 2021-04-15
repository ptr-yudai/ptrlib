import random
import string

def random_primitive():
    """Generate a random primitive object
    """
    t = random.randint(0, 4)
    if t == 0:
        return random_int(-0xffffffff, 0xffffffff)
    elif t == 1:
        return random_float(-3.40282347E+38 , 3.40282347E+38)
    elif t == 2:
        return random_bool()
    elif t == 3:
        return random_bytes(0x100)
    elif t == 4:
        return random_str(0x100)

def random_dict(max_depth, nmin, nmax=0, dict_p=0.25, gen=None, depth=0):
    """Generate a random dictionary

    Args:
        max_depth (int): Maximum depth of the list
        nmin (int): Minimum length of the list
        nmax (int): Maximum length of the list
        dict_p (float): Probability that generates dict (not used in the bottom)
        gen (func): Function to generate the elements. This function must receive two arguments `is_key` and `depth`. `is_key` is True when it's generating the key of dictionary. It's always False when generating an element of a list. `depth` represents the current depth and is more than or equals to 0.

    Returns:
        dict: Generated dictionary
    """
    def default_gen(is_key=False, depth=0):
        return random_primitive()

    if nmin < 0:
        nmin = 0
    if nmax == 0:
        nmax = nmin
        nmin = 0
    elif nmax < nmin:
        nmin, nmax = nmax, nmin

    if gen is None:
        gen = default_gen

    result = {}
    num = random.randint(nmin, nmax)
    for i in range(num):
        key = value = gen(is_key=True, depth=depth)
        if random.random() <= dict_p and max_depth > 1:
            value = random_dict(max_depth-1, nmin, nmax,
                                dict_p=dict_p, gen=gen, depth=depth+1)
        else:
            value = gen(is_key=False, depth=depth)
        result[key] = value
    return result

def random_list(max_depth, lmin, lmax=0, list_p=0.25, gen=None, depth=0):
    """Generate a random list

    Args:
        max_depth (int): Maximum depth of the list
        lmin (int): Minimum length of the list
        lmax (int): Maximum length of the list
        list_p (float): Probability that generates list (not used in the bottom)
        gen (func): Function to generate the elements. See the document of `random_dict` for more details.

    Returns:
        list: Generated list
    """
    def default_gen(is_key=False, depth=0):
        return random_primitive()

    if lmin < 0:
        lmin = 0
    if lmax == 0:
        lmax = lmin
        lmin = 0
    elif lmax < lmin:
        lmin, lmax = lmax, lmin

    if gen is None:
        gen = default_gen

    result = []
    length = random.randint(lmin, lmax)
    for i in range(length):
        if random.random() <= list_p and max_depth > 1:
            result.append(random_list(max_depth-1, lmin, lmax,
                                      list_p=list_p, gen=gen, depth=depth+1))
        else:
            result.append(gen(is_key=False, depth=depth))
    return result

def random_bool(true_p=0.5):
    """Generate true of false randomly

    Args:
        true_p (float): Probability of generating true

    Returns:
        bool: True or false
    """
    return random.random() <= true_p

def random_int(lmin, lmax=None):
    """Generate a random integer

    Args:
        lmin (int): Minimum value
        lmax (int): Maximum value

    Returns:
        int: Random integer
    """
    if lmax is None:
        lmin, lmax = 0, lmin
    if lmax < lmin:
        lmin, lmax = lmax, lmin
    return random.randint(lmin, lmax)

def random_float(lmin, lmax=None):
    """Generate a random float value

    Args:
        lmin (int): Minimum value
        lmax (int): Maximum value

    Returns:
        float: Random float value
    """
    if lmax is None:
        lmin, lmax = 0.0, lmin
    return random.uniform(lmin, lmax)

def random_str(lmin, lmax=0, charset=None):
    """Generate a random byte array

    Args:
        lmin    (int) : Minimum number of bytes
        lmax    (int) : Maximum number of bytes

    Returns:
        str: Random string
    """
    if lmin < 0:
        lmin = 0
    if lmax == 0:
        lmax = lmin
        lmin = 0
    elif lmax < lmin:
        lmin, lmax = lmax, lmin

    if charset is None:
        charset = string.printable[:-5]

    return ''.join([random.choice(charset) \
                    for i in range(lmin)]) \
        + ''.join([random.choice(charset) \
                   for i in range(random.randint(0, lmax-lmin))])

def random_bytes(lmin, lmax=0, charset=None):
    """Generate a random byte array

    Args:
        lmin    (int) : Minimum number of bytes
        lmax    (int) : Maximum number of bytes
        charset (list): List of bytes to be used

    Returns:
        bytes: Random byte array
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
    elif isinstance(charset, str):
        charset = list(map(ord, list(charset)))

    return bytes([random.choice(charset)
                  for i in range(lmin)]) \
        + bytes([random.choice(charset)
                 for i in range(random.randint(0, lmax-lmin))])
