from ptrlib.arch.linux import *


def which(s):
    # TODO: Separate Windows support based on running OS
    return which_linux(s)