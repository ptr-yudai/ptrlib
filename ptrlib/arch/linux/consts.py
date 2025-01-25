import contextlib
import functools
import os
import platform
import re
import subprocess
import tempfile
from typing import List, Optional, Union
from ptrlib.arch.arm import is_arch_arm, ConstsTableArm
from ptrlib.arch.intel import is_arch_intel, ConstsTableIntel

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


_TEMPLATE_C = """
#include <stdio.h>
#include <{0}>

#define print_const(X) (void)_Generic((X),   \
  char*: printf("S:%s\\n", (const char*)(X)), \
  default: printf("V:%lu\\n", (size_t)(X))    \
)

int main() {{
  print_const({1});
  return 0;
}}
"""

# ConstsTableLinux: Experimental feature
class ConstsTableLinux(object):
    def resolve_constant(self,
                         const: str,
                         include_path: Optional[List[str]] = None) -> Union[int, str]:
        from ptrlib.arch.common import which

        if len(const) == 0:
            raise KeyError("Empty name '{}'".format(const))

        if include_path is not None:
            include_path = include_path + ['/usr/include']
        else:
            include_path = ['/usr/include']

        def heuristic_redirect(path: str) -> str:
            """Convert include path"""
            with open(path, 'r') as f:
                buf = f.read()
                found = re.findall(r"Never use <.+> directly; include <(.+)> instead\.", buf)
                if found:
                    return found[0]
                else:
                    return path

        def test_constant(path: str, name: str, gcc_path: str) -> Optional[Union[int, str]]:
            """Compile and run C code to get constant value"""
            path = heuristic_redirect(path)
            fname_c   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.c'
            fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.bin'
            with open(fname_c, 'w') as f:
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
                            raise RuntimeError(f"Unexpected output: {p.stdout.decode()}")

                        return

        # We rely on grep since it's much faster
        grep_path = which('grep')
        if grep_path is None:
            raise FileNotFoundError("'grep' not found")

        if is_arch_intel(platform.machine()):
            gcc_path = which('gcc')
        else:
            gcc_path = which('x86_64-linux-gnu-gcc')
        if gcc_path is None:
            raise FileNotFoundError("Install 'gcc' for this architecture")

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

        raise KeyError("Could not find constant: {}".format(const))

    @cache
    def __getitem__(self, const_or_arch: str) -> Union[int, str, ConstsTableIntel, ConstsTableArm]:
        if is_arch_intel(const_or_arch):
            return ConstsTableIntel()
        elif is_arch_arm(const_or_arch):
            return ConstsTableArm()
        elif const_or_arch.isupper():
            return self.resolve_constant(const_or_arch)
        else:
            raise KeyError("Invalid name '{}'".format(arch))

    def __getattr__(self, arch: str):
        return self[arch]


consts = ConstsTableLinux()
