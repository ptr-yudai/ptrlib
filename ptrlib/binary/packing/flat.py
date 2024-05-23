from typing import Callable, List, Optional, TypeVar, Union, overload

_T = TypeVar("_T")
_U = TypeVar("_U")

@overload
def flat(chunks: List[_T], map: None=None) -> _T: ...

@overload
def flat(chunks: List[_T], map: Optional[Callable[[_T], _U]]=None) -> _U: ...

def flat(chunks: List[_T], map: Optional[Callable[[_T], _U]]=None) -> Union[_T, _U]:
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

