"""This package provides `flat` function.
"""
from typing import Any, Callable, List


def flat(chunks: List[Any], map: Callable[[Any], bytes]) -> bytes:
    """Concatnate chunks into bytes.

    Args:
        chunks (List[int]): The chunks to concatenate.
        map (Callable[[int], bytes]): A function that converts each element into bytes.

    Returns:
        bytes: The concatenated chunks.

    Examples:
        ```
        a = flat([1, 2, 3], p32)
        b = p32(1) + p32(2) + p32(3)
        assert a == b
        ```
    """
    assert isinstance(chunks, list), f"flat: {type(chunks)} given ('list' expected)"

    if len(chunks) == 0:
        return b''

    result = map(chunks[0])
    for i in range(1, len(chunks)):
        result += map(chunks[i])

    return result


__all__ = ['flat']
