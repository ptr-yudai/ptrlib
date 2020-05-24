from logging import getLogger

logger = getLogger(__name__)

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
    logger.warn("`disasm` is no longer supported")
    logger.warn("Use disasm.pro instead :P")
