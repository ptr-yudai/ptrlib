from .byteconv import str2bytes
from typing import Union

def hexdump(data: Union[str, bytes], prefix: str='', postfix: str=''):
    """Print data in hexdump format
    """
    if isinstance(data, str):
        data = str2bytes(data)
    prev_display = True

    for offset in range(0, len(data), 0x10):
        output  = prefix
        output += f"{offset:08x}  "

        for i, c in enumerate(data[offset:offset+0x10]):
            if i == 8: output += " "
            output += f"{c:02x} "
        if len(data[offset:]) < 0x10:
            output += "   " * (0x10 - len(data[offset:]))
            if len(data[offset:]) < 9:
                output += " "
        output += " |"

        for c in data[offset:offset+0x10]:
            if 0x20 <= c <= 0x7e:
                output += chr(c)
            else:
                output += "."
        output += "|" + postfix

        if offset > 0x10 and data[offset-0x10:offset] == data[offset:offset+0x10]:
            if prev_display:
                print(prefix + "*" + postfix)
                prev_display = False
        else:
            print(output)
            prev_display = True
