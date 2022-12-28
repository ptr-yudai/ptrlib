import subprocess
from logging import getLogger

logger = getLogger(__name__)


def disassemble(code, bits=None, arch='intel'):
    raise NotImplementedError()

def disasm(code,
           arch='x86',
           mode='64',
           endian='little',
           address=0,
           micro=False,
           mclass=False,
           v8=False,
           v9=False,
           returns=list):
    raise NotImplementedError()
