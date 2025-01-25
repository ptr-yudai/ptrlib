import functools
from typing import Union

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


class ConstsTableIntel(object):
    @cache
    def __getitem__(self, name: str) -> Union[int, str]:
        from ptrlib.arch.linux import consts
        return consts.resolve_constant(
            name,
            ['/usr/include/x86_64-linux-gnu',
             '/usr/include/x86_64-linux-musl']
        )

    def __getattr__(self, name: str):
        return self[name]
