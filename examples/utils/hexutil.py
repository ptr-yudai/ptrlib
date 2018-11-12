from ptrlib import *

ascii_data = "This is a test."
hex_data = "414243313233"
int_data = 0x616263393837

print("===== From Ascii =====")
print("Ascii: {0}".format(ascii_data))
print("Hex  : {0}".format(str2hex(ascii_data)))
print("Int  : {0}".format(str2int(ascii_data)))

print("===== From Hex =====")
print("Ascii: {0}".format(hex2str(hex_data)))
print("Hex  : {0}".format(hex_data))
print("Int  : {0}".format(hex2int(hex_data)))

print("===== From Integer =====")
print("Ascii: {0}".format(int2str(int_data)))
print("Hex  : {0}".format(int2hex(int_data)))
print("Int  : {0}".format(int_data))

