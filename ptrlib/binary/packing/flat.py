from typing import Callable, List, Optional, TypeVar, Union, overload

_T = TypeVar("_T")
_U = TypeVar("_U")

@overload
def flat(chunks: List[List[_T]], map: None=None) -> List[_T]: ...

@overload
def flat(chunks: List[_T], map: Callable[[_T], List[_U]]) -> List[_U]: ...

def flat(chunks: Union[List[List[_T]], List[_T]], map: Optional[Callable[[_T], List[_U]]]=None) -> Union[List[_T], List[_U]]:
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

