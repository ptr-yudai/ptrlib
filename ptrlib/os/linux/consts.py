"""Linux constants resolver (experimental).

This moves ptrlib.arch.linux.consts into ptrlib.os.linux.consts without changing
its public API. It provides:
- consts.resolve_constant(NAME[, include_path]) -> int | str
- consts.NAME for uppercase macros (via __getitem__/__getattr__)
"""
from __future__ import annotations

import contextlib
import functools
import os
import re
import subprocess
import tempfile

try:
    cache = functools.cache  # type: ignore[attr-defined]
except AttributeError:  # Python < 3.9 fallback
    cache = functools.lru_cache


_TEMPLATE_C = """
#include <stdio.h>
#include <{0}>

#define print_const(X) (void)_Generic((X),   \
  char*: printf("S:%s\n", (const char*)(X)), \
  default: printf("V:%lu\n", (size_t)(X))    \
)

int main() {{
  print_const({1});
  return 0;
}}
"""


class ConstsTableLinux:
    def resolve_constant(self,
                         const: str,
                         include_path: list[str] | None = None) -> int | str:
        from ptrlib.os import which

        if len(const) == 0:
            raise KeyError(f"Empty name '{const}'")

        if include_path is not None:
            include_path = include_path + ['/usr/include']
        else:
            include_path = ['/usr/include']

        def heuristic_redirect(path: str) -> str:
            """Convert include path"""
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                buf = f.read()
                found = re.findall(r"Never use <.+> directly; include <(.+)> instead\.", buf)
                if found:
                    return found[0]
                else:
                    return path

        def test_constant(path: str, name: str, gcc_path: str) -> int | str | None:
            """Compile and run C code to get constant value"""
            path = heuristic_redirect(path)
            fname_c   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.c'
            fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.bin'
            with open(fname_c, 'w', encoding='utf-8') as f:
                f.write(_TEMPLATE_C.format(path, name))

            with contextlib.suppress(FileNotFoundError):
                p = subprocess.run([gcc_path, fname_c, '-o', fname_bin],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                os.unlink(fname_c)

                if p.returncode == 0:
                    p = subprocess.run([fname_bin],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    os.unlink(fname_bin)

                    if p.returncode == 0:
                        if p.stdout.startswith(b"S:"):
                            return p.stdout[2:].decode().strip()
                        elif p.stdout.startswith(b"V:"):
                            return int(p.stdout[2:])
                        else:
                            raise RuntimeError(f"Unexpected output: {p.stdout.decode(errors='ignore')}")

                    return None

            return None

        # We rely on grep since it's much faster
        grep_path = which('grep')
        if grep_path is None:
            raise FileNotFoundError("'grep' not found")

        # Prefer native gcc
        gcc_path = which('gcc')
        if gcc_path is None:
            raise FileNotFoundError("Install 'gcc'")

        for dpath in include_path:
            # We can directly build regex since `const` is a valid Python variable name
            p = subprocess.run([grep_path, '-E', f'#\\s*define\\s+{const}', '-rl', dpath],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if p.returncode != 0:
                continue

            for path in p.stdout.decode().split('\n'):
                if not os.path.exists(path):
                    continue

                c = test_constant(path, const, gcc_path)
                if c is not None:
                    return c

        raise KeyError(f"Could not find constant: {const}")

    @cache
    def __getitem__(self, const: str) -> int | str:
        if const.isupper():
            return self.resolve_constant(const)
        raise KeyError(f"Invalid name '{const}'")

    def __getattr__(self, name: str):
        return self[name]


consts = ConstsTableLinux()

__all__ = ['consts', 'ConstsTableLinux']

