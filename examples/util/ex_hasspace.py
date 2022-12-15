#!/usr/bin/env python
from ptrlib import *

payload = 'Hello,\tWorld!'
print("is_scanf_safe('{}')={}".format(payload, is_scanf_safe(payload)))
is_scanf_safe(payload, warn=True)
print("is_fgets_safe('{}')={}".format(payload, is_fgets_safe(payload)))
is_fgets_safe(payload, warn=True)

print("-"*10)

payload = p64(0xdeadbeef) + p64(0x400a20)
print("is_scanf_safe('{}')={}".format(payload, is_scanf_safe(payload)))
is_scanf_safe(payload, warn=True)
print("is_fgets_safe('{}')={}".format(payload, is_fgets_safe(payload)))
is_fgets_safe(payload, warn=True)


