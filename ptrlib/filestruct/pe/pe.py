import functools
import os
from logging import getLogger
from typing import Optional
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
        raise NotImplementedError()

    def symbol(self, name):
        """Get the address corresponding to a symbol
        """
        if isinstance(name, str):
            name = str2bytes(name)

        for a in self._parser.iter_imports():
            print(a)

        for image_symbol, image_aux_symbol in self._parser.iter_symbol_table():
            print(image_symbol['Name'], hex(image_symbol['Value']))


    def section(self, name):
        raise NotImplementedError()

    def iat(self, dll_or_func: str, func: Optional[str] = None):
        """IAT entry

        Examples:
            pe.iat("Sleep")
            pe.iat("kernel32.dll", "Sleep")
        """
        if func is None:
            dll_name, func_name = None, dll_or_func
        else:
            dll_name, func_name = dll_or_func, func

        if isinstance(dll_name, bytes):
            dll_name = bytes2str(dll_name)
        if isinstance(func_name, bytes):
            func_name = bytes2str(func_name)

        for table in self._parser.iter_imports():
            # Compare DLL name if specified
            if dll_name is not None and \
               table['Name'].lower() != dll_name.lower():
                continue

            for addr, name in self._parser.iter_iat(table):
                if name == func_name:
                    return addr

    def imports(self):
        """Get all imports
        """
        imports = {}
        for table in self._parser.iter_imports():
            imports[table['Name']] = [
                name for _, name in self._parser.iter_iat(table)
            ]
        return imports

    def exports(self):
        raise NotImplementedError()

    def resources(self):
        raise NotImplementedError()

