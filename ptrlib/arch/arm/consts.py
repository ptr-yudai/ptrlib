import functools
from typing import Union

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


class ConstsTableArm(object):
    @cache
    def __getitem__(self, name: str) -> Union[int, str]:
        raise NotImplementedError("ARM is not supported yet")

    def __getattr__(self, name: str):
        return self[name]
