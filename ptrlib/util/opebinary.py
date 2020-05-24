def chunks(data, size, padding=None):
    """Split data into chunks
    Args:
        data      : The target data to split
        size (int): The size of each chunk
        padding   : Data for padding (None if not to add padding)

    Returns:
        list: split chunks
    """
    assert size > 0
    result = []
    for i in range(0, len(data), size):
        result.append(data[i:i+size])
    if padding is not None and len(data) % size > 0:
        result[-1] += padding * (size - (len(data) % size))
    return result

def flat(chunks, map=None):
    """Concatnate chunks into a data
    Aimed for the use of crafting ROP chains

    Args:
        chunks    : The target chunks to concat

    Returns:
        bytes: split chunks
    """
    assert isinstance(chunks, list)
    result = chunks[0] if map is None else map(chunks[0])
    for i in range(1, len(chunks)):
        result += chunks[i] if map is None else map(chunks[i])
    return result

