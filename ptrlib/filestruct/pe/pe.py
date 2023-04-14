import functools
import os
from logging import getLogger
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

