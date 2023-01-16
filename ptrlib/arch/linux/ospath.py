import os
import subprocess


def which_linux(s: str) -> str:
    if '/' not in s:
        try:
            s = subprocess.check_output(["which", s]).decode().rstrip()
        except subprocess.CalledProcessError:
            raise FileNotFoundError("'{}' not found".format(s))
    elif not os.path.isfile(s):
        raise FileNotFoundError("{}: File not found".format(s))
    return s
