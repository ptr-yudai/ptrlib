def flat(chunks, map=None):
    """Concatnate chunks into a data
    Aimed for the use of crafting ROP chains

    Args:
        chunks    : The target chunks to concat

    Returns:
        bytes: split chunks
    """
    assert isinstance(chunks, list), "Invalid input"

    result = chunks[0] if map is None else map(chunks[0])
    for i in range(1, len(chunks)):
        result += chunks[i] if map is None else map(chunks[i])

    return result

