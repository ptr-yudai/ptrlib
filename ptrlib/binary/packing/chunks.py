"""This package provides `chunks` function.
"""
from logging import getLogger
from typing import Any

DataType = str | bytes | list[Any]

logger = getLogger(__name__)

def chunks(data: DataType,
           size: int,
           padding: DataType | None = None) -> list[Any]:
    """Split data into chunks.

    Args:
        data (str | bytes | list[Any]): The data to split.
        size (int): The size of each chunk.
        padding (str | bytes | list[Any], optional):
            Data for padding (None if not to add padding)

    Returns:
        list: Split chunks.
    """
    assert size > 0, "Invalid chunk size"

    result = []
    for i in range(0, len(data), size):
        result.append(data[i:i+size])

    if padding is not None and len(data) % size > 0:
        result[-1] += padding * (size - (len(data) % size))

    return result


__all__ = ['chunks']
