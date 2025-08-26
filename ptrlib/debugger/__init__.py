import os

if os.name == 'nt':
    #from .windows import *
    pass
else:
    from .unix import *
