import os
import shutil
import subprocess


def which(s: str) -> str | None:
    """Cross-platform executable resolver.

    Prefer Python's shutil.which for robust PATH/PATHEXT handling.
    Falls back to platform utilities only if necessary.

    Behavior:
      - If ``s`` contains a path separator, return it if it points to a file.
      - Else, search PATH using shutil.which and return the first resolved file.
      - On Windows, handles PATHEXT and avoids the multi-line pitfalls of ``where``.
    """
    is_windows = os.name == 'nt'

    # If caller provides a path-like string, just validate it
    if ('/' in s) or ('\\' in s):
        return s if os.path.isfile(s) else None

    # Primary: shutil.which
    path = shutil.which(s)
    if path and os.path.isfile(path):
        return path

    # Fallback: platform utilities (best-effort)
    try:
        if is_windows:
            out = subprocess.check_output(["where.exe", s])
        else:
            out = subprocess.check_output(["which", s])
        # Take the first non-empty existing path
        for line in out.decode(errors='ignore').splitlines():
            cand = line.strip().strip('\"')
            if cand and os.path.isfile(cand):
                return cand
    except Exception:
        pass
    return None


__all__ = ['which']
