#!/usr/bin/env python
from ptrlib import *
import string

# basic usage
print(consists_of("abc", string.printable))
print(consists_of("abc\x01\x02\x03", string.printable))

# returns the ratio
print("=" * 20)
print(consists_of("abc", string.printable, returns=float))
print(consists_of("abc\x01\x02\x03", string.printable, returns=float))

# can apply different types
print("=" * 20)
print(consists_of(b"abc", string.printable))
print(consists_of(["1", "1", "3"], ["1", "2", "3"]))

# can specify threathold
print("=" * 20)
print(consists_of("abc\1\2\3", string.printable, per=1.0))
print(consists_of("abc\1\2\3", string.printable, per=0.8))
print(consists_of("abc\1\2\3", string.printable, per=0.6))
print(consists_of("abc\1\2\3", string.printable, per=0.4))
print(consists_of("abc\1\2\3", string.printable, per=0.2))
