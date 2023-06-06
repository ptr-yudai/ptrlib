import os
from typing import Optional
from ptrlib.arch.linux import *
from ptrlib.arch.windows import *

_is_windows = os.name == 'nt'


def which(s: str) -> Optional[str]:
    if _is_windows:
        return which_windows(s)
    else:
        return which_linux(s)
