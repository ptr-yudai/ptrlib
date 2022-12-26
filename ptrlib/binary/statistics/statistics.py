from logging import getLogger
from typing import List, Type, TypeVar, Union

logger = getLogger(__name__)

_T = TypeVar("_T", float, bool)

def get_frequency(*args):
    raise NotImplementedError("ptrlib.binary.statistics.get_frequency")

def consists_of(text: Union[str, bytes, List[int]], charset: Union[str, bytes, List[str]], per: float=1.0, returns: Type[_T]=bool) -> _T:
    """Checks if the text consists of given charset.

    Args:
        text       : Target object (list/bytes/str)
        charset    : Allowed elements (list/bytes/str)
        per (float): Threathold
        returns    : Type of return value (bool/float)

    Returns:
        bool: true if text consists of characters in charset
    """
    target = []
    if isinstance(text, list):
        target = text
    elif isinstance(text, str):
        target = list(map(ord, list(text)))
    elif isinstance(text, bytes):
        target = list(text)
    else:
        raise ValueError("Expected 'list'/'str'/'bytes' but '{}' given for `text`".format(type(text)))

    allowed = []
    if isinstance(charset, list):
        allowed = charset
    elif isinstance(charset, str):
        allowed = list(map(ord, list(charset)))
    elif isinstance(charset, bytes):
        allowed = list(charset)
    else:
        raise ValueError("Expected 'list'/'str'/'bytes' but '{}' given for `charset`".format(type(text)))

    count = 0
    for elm in target:
        if elm in allowed:
            count += 1

    if returns == bool:
        return count / len(target) >= per
    else:
        return count / len(target)
