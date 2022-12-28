def chunks(data, size, padding=None, map=None):
    """Split data into chunks
    Args:
        data      : The target data to split
        size (int): The size of each chunk
        padding   : Data for padding (None if not to add padding)

    Returns:
        list: split chunks
    """
    assert size > 0, "Invalid chunk size"

    result = []
    for i in range(0, len(data), size):
        result.append(data[i:i+size] if map is None else map(data[i:i+size]))

    if padding is not None and len(data) % size > 0:
        result[-1] += padding * (size - (len(data) % size))

    return result
