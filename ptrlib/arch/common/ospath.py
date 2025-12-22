import os
from ptrlib.arch.linux import *
from ptrlib.arch.windows import *

_is_windows = os.name == 'nt'


def which(s: str) -> str | None:
    if _is_windows:
        return which_windows(s)
    else:
        return which_linux(s)
