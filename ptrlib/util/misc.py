from ptrlib.util.encoding import *
from logging import getLogger

logger = getLogger(__name__)

def extract_flag(haystack, nee='FLAG{', dle='}'):
    """Extract a block which matches to the pattern of flag from given text.

    Args:
        haystack: Target object (list/bytes/str)
        nee     : Beginning pattern of the flag
        dle     : End pattern of the flag

    Returns:
        list: list of found patterns
    """
    result = []
    neeList = []
    dleList = []
    target = None
    if isinstance(haystack, list):
        target = haystack
    elif isinstance(haystack, bytes):
        target = bytes2str(haystack)
    elif isinstance(haystack, str):
        target = haystack
    else:
        logger.warn("Expected 'list'/'str'/'bytes' but '{}' given for `haystack`".format(type(haystack)))

    if not isinstance(target, list) and isinstance(nee, bytes):
        nee = bytes2str(nee)
    if not isinstance(target, list) and isinstance(dle, bytes):
        dle = bytes2str(dle)

    ofs = 0
    while nee in target[ofs:]:
        x = target.index(nee, ofs)
        neeList.append(x)
        ofs = x + 1
    ofs = 0
    while dle in target[ofs:]:
        x = target.index(dle, ofs)
        dleList.append(x)
        ofs = x + 1

    if neeList != [] and dleList != []:
        for s in neeList:
            for e in dleList:
                if s >= e: continue
                if isinstance(dle, str):
                    result.append(target[s:e + len(dle)])
                else:
                    result.append(target[s:e + 1])
                    
    return result

def consists_of(text, charset, per=1.0, returns=bool):
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
        logger.warn("Expected 'list'/'str'/'bytes' but '{}' given for `text`".format(type(text)))

    allowed = []
    if isinstance(charset, list):
        allowed = charset
    elif isinstance(charset, str):
        allowed = list(map(ord, list(charset)))
    elif isinstance(charset, bytes):
        allowed = list(charset)
    else:
        logger.warn("Expected 'list'/'str'/'bytes' but '{}' given for `charset`".format(type(text)))
    
    count = 0
    for elm in target:
        if elm in allowed:
            count += 1
    
    if returns == bool:
        return True if count / len(target) >= per else False
    else:
        return count / len(target)
