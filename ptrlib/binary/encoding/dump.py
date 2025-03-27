"""This package provides the hexdump function.
"""
from typing import Union
from .byteconv import str2bytes

def hexdump(data: Union[str, bytes], prefix: str='', postfix: str=''):
    """Print data in hexdump format.

    Args:
        data (bytes): The data to dump.
        prefix (str): Prefix string prepended for each line.
        postfix (str): Postfix string appended for each line.
    """
    if isinstance(data, str):
        data = str2bytes(data)
    data = bytes(data)

    prev_display = True

    for offset in range(0, len(data), 0x10):
        # Address
        output  = prefix
        output += f"{offset:08x}  "

        # Data
        for i, c in enumerate(data[offset:offset+0x10]):
            if i == 8:
                output += " "
            output += f"{c:02x} "

        if len(data[offset:]) < 0x10:
            output += "   " * (0x10 - len(data[offset:]))
            if len(data[offset:]) < 9:
                output += " "
        output += " |"

        # ASCII
        for c in data[offset:offset+0x10]:
            if 0x20 <= c <= 0x7e:
                output += chr(c)
            else:
                output += "."
        output += "|" + postfix

        # Omit the same lines
        if offset > 0x10 and data[offset-0x10:offset] == data[offset:offset+0x10]:
            if prev_display:
                print(prefix + "*" + postfix)
                prev_display = False
        else:
            print(output)
            prev_display = True


__all__ = ['hexdump']
