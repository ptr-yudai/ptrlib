import functools
import os
from logging import getLogger
from typing import Optional, Union
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
        """Get all symbols
        """
        symbols = {}
        for image_symbol, image_aux_symbol in self._parser.iter_symbol_table():
            # TODO: Add base address
            symbols[image_symbol['Name']] = image_symbol['Value']
        return symbols

    def symbol(self,
               name: Union[str, bytes],
               exact: Optional[bool] = False) -> Optional[int]:
        """Get the address corresponding to a symbol
        """
        if isinstance(name, str):
            name = str2bytes(name)

        for image_symbol, image_aux_symbol in self._parser.iter_symbol_table():
            at = image_symbol['Name'].rfind(b'@')
            if image_symbol['Name'] == name:
                # Exact match
                # TODO: Add base address
                return image_symbol['Value']

            elif not exact and at > 0 and \
                 image_symbol['Name'][at+1:].isdigit() and \
                 image_symbol['Name'][:at] == name:
                # Match "SYMBOL@num" given "SYMBOL"
                # TODO: Add base address
                return image_symbol['Value']

        if exact:
            return None

        # Search for "__imp__FUNC@num" given "FUNC"
        for image_symbol, image_aux_symbol in self._parser.iter_symbol_table():
            at = image_symbol['Name'].rfind(b'@')
            if at > 0 and \
               image_symbol['Name'][at+1:].isdigit() and \
               image_symbol['Name'].startswith(b'__imp__') and \
               image_symbol['Name'][7:at] == name:
                # TODO: Add base address
                return image_symbol['Value']

        return None

    def sections(self):
        """Get all section names

        Returns:
            dict: Dictionary with section name in key and
                  address of the section name in value.
        """
        return {
            # TODO: Add base address
            section['Name']: section['VirtualAddress']
            for section in self._parser.iter_sections()
        }

    def section(self, name: Union[str, bytes]):
        """Get address of a section

        Args:
            name (str): Section name

        Returns:
            int: Address of the section name, or None if not found
        """
        if isinstance(name, bytes):
            name = bytes2str(name)

        for section in self._parser.iter_sections():
            if section['Name'] == name:
                # TODO: Add base address
                return section['VirtualAddress']

    def iat(self,
            dll_or_func: Union[str, bytes],
            func: Optional[Union[str, bytes]] = None):
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
                    # TODO: Add base address
                    return addr

    def imports(self):
        """Get all imports

        Returns:
            dict: Dictionary with DLL name in key,
                  list of function names in value of each key.
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

