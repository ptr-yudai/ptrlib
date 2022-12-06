import os
from .structs import *

class ELF(object):
    def __init__(self, filepath):
        """ELF Parser
        """
        self.filepath = os.path.realpath(filepath)
        self._elf = ELFFile(self.filepath)

