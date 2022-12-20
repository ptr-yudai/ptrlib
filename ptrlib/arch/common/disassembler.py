from logging import getLogger
from typing import Optional

logger = getLogger(__name__)


def disassemble(code: bytes, bits: Optional[int]=None, arch: str='intel'):
    raise NotImplementedError()

def disasm(code: bytes,
           arch: str='x86',
           mode: str='64',
           endian: str='little',
           address: int=0,
           micro: bool=False,
           mclass: bool=False,
           v8: bool=False,
           v9: bool=False,
           returns: type=list):
    raise NotImplementedError()
