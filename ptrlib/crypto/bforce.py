import string

def brute_force_pattern(pattern, table=string.printable):
    """ Conver a pattern list into a string
    
    The generator `brute_force_attack` yields pattern lists,
    and you have to call this function in order to get a valid
    string.
    """
    return ''.join(table[i] for i in pattern)

def brute_force_attack(length, pattern=None, table_len=len(string.printable)):
    """ Brute-Force attack
    
    Do a brute force search for `length` bytes string which consist of
    the characters in a table of `table_len` bytes.
    This generator yields a pattern list.
    You have to call `brute_force_pattern` to convert the list into a string.
    Even after once interrupting the search, you can resume the search
    by calling `brute_force_restart` and passing the pattern list as `pattern`.
    """
    if table_len <= 0:
        raise ValueError("Invalid table size")
    if length <= 0:
        raise ValueError("The value of `length` must be more than 0")
    if pattern is None:
        # Initial value
        for i in range(table_len):
            for ret in brute_force_attack(length, table_len=table_len, pattern=[i]):
                yield ret
    else:
        if len(pattern) == length:
            # Generate a complete pattern
            yield list(pattern)
        else:
            # Grow the pattern
            for i in range(table_len):
                for ret in brute_force_attack(length, table_len=table_len, pattern=list(pattern + [i])):
                    yield ret
