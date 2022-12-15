#!/usr/bin/env python
from ptrlib import *

## Hello, World!
print("===== Hello, World! =====")
# MD5
md5 = MD5()
md5.update("Hello, ")
md5.update("World!")
print("   md5('Hello, World!') = " + md5.hexdigest())
# SHA-1
sha1 = SHA1()
sha1.update("Hello, ")
sha1.update("World!")
print("  sha1('Hello, World!') = " + sha1.hexdigest())
# SHA-256
sha256 = SHA256()
sha256.update("Hello, ")
sha256.update("World!")
print("sha256('Hello, World!') = " + sha256.hexdigest())

## Lorem ipsum
print("===== Lorem ipsum =====")
lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
md5.reset()
sha1.reset()
sha256.reset()
md5.update(lorem)
sha1.update(lorem)
sha256.update(lorem)
print("   md5(lorem ipsum) = " + md5.hexdigest())
print("  sha1(lorem ipsum) = " + sha1.hexdigest())
print("sha256(lorem ipsum) = " + sha256.hexdigest())
