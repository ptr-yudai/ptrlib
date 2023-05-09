import functools
import os
from logging import getLogger
from ptrlib.binary.encoding import str2bytes
from .parser import PEParser

logger = getLogger(__name__)

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


class PE(object):
    def __init__(self, filepath):
        """PE Parser
        """
        self.filepath = os.path.realpath(filepath)
        self._parser = PEParser(self.filepath)
        self._base = 0

    def symbols(self):
        return

    def symbol(self, name):
        """Get 
        """
        if isinstance(name, str):
            name = str2bytes(name)

        for image_symbol, image_aux_symbol in self._parser.iter_symbol_table():
            print(image_symbol['Name'], hex(image_symbol['Value']))


    def section(self, name):
        raise NotImplementedError()

    def iat(self, name):
        raise NotImplementedError()

    def exports(self):
        raise NotImplementedError()

    def imports(self):
        for table in self._parser.iter_imports():
            print(table)

    def resources(self):
        raise NotImplementedError()

