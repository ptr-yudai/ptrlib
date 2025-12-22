import os
import subprocess


def which_windows(s: str) -> str | None:
    if '/' not in s:
        try:
            s = subprocess.check_output(["where.exe", s]).decode().rstrip()
        except subprocess.CalledProcessError:
            s = None
    elif not os.path.isfile(s):
        s = None
    return s
