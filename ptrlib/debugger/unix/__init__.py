import os

if os.name != 'nt':
    from .debug import *
    from .process import *
