#!/usr/bin/env python
from ptrlib import *

msg1 = """
Congratulations!
Here is your flag: FLAG{dummy_flag_1}
"""

msg2 = b"""
flag{here_is_flag{this_is_flag{dummy_flag_2}
"""

msg3 = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4, 6, 2]

print(extract_flag(msg1))
print(extract_flag(msg2, 'flag{', '}'))
print(extract_flag(msg3, 9, 9))
