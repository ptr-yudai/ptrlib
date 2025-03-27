"""This package provides `chunks` function.
"""
from typing import Any, Callable, List, Optional, Union

DataType = Union[str, bytes, List[Any]]

def chunks(data: DataType,
           size: int,
           padding: Optional[DataType]=None,
           map: Optional[Callable[[DataType], Any]]=None) -> List[Any]:
    """Split data into chunks.

    Args:
        data (Union[str, bytes, List[Any]]): The data to split.
        size (int): The size of each chunk.
        padding (Union[str, bytes, List[Any]], optional):
            Data for padding (None if not to add padding)
        map (Callable[[Union[str, bytes, List[Any]]], Any], optional):
            A function that converts each chunk.

    Returns:
        list: Split chunks.
    """
    assert size > 0, "Invalid chunk size"

    result = []
    for i in range(0, len(data), size):
        if map is None:
            result.append(data[i:i+size])
        else:
            result.append(map(data[i:i+size]))

    if padding is not None and len(data) % size > 0:
        result[-1] += padding * (size - (len(data) % size))

    return result


__all__ = ['chunks']
