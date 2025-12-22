import os
import subprocess


def which(s: str) -> str | None:
    """Cross-platform executable resolver.

    On POSIX, uses `which`; on Windows, uses `where.exe`.
    Returns the absolute path if found, otherwise None. If a path-like string
    with '/' (or '\\' on Windows) is provided, validates its existence.
    """
    is_windows = os.name == 'nt'

    if ('/' in s) or ('\\' in s):
        return s if os.path.isfile(s) else None

    try:
        if is_windows:
            out = subprocess.check_output(["where.exe", s])
        else:
            out = subprocess.check_output(["which", s])
        path = out.decode(errors='ignore').strip()
        return path if os.path.isfile(path) else None
    except subprocess.CalledProcessError:
        return None


__all__ = ['which']

