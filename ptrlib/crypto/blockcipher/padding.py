from ptrlib.binary.encoding import str2bytes
from logging import getLogger
try:
    from typing import Literal
except:
    from typing_extensions import Literal


logger = getLogger(__name__)


def pad(data: bytes, size: int, mode: Literal['pkcs#5', 'zero']='pkcs#5') -> bytes:
    """Append padding

    Args:
        data (bytes) : Data to append padding to
        size (int)   : Block size
        mode (str)   : Padding mode

    Available modes:
      zero  : Zero byte padding
      pkcs#5: PKCS#5 Padding
    """
    mode = mode.lower()
    if mode not in ['zero', 'pkcs#5']:
        logger.warning("Invalid padding mode. Using 'PKCS#5'")
        logger.warning("Choose from zero / pkcs#5")
        mode = 'pkcs#5'

    if isinstance(data, str):
        data = str2bytes(data)

    if size <= 0:
        logger.warning("Block size must be bigger than zero")
        return data

    if mode == 'zero':
        # Zero byte padding
        return data + b'\x00' * (size - (len(data) % size))

    elif mode == 'pkcs#5':
        # PKCS#5
        padlen = size - (len(data) % size)
        if padlen > 255:
            logger.warning("Padding length cannot be bigger than 0xff in PKCS#5")
            padlen %= 0x100
        return data + bytes([padlen]) * padlen

def unpad(data: bytes, mode: Literal['pkcs#5', 'zero']='pkcs#5') -> bytes:
    """Remove padding

    Args:
        data (bytes) : Data to append padding to
        mode (str)   : Padding mode

    Available modes:
      zero  : Zero byte padding
      pkcs#5: PKCS#5 Padding
    """
    mode = mode.lower()
    if mode not in ['zero', 'pkcs#5']:
        logger.warning("Invalid padding mode. Using 'PKCS#5'")
        logger.warning("Choose from zero / pkcs#5")
        mode = 'pkcs#5'

    if isinstance(data, str):
        data = str2bytes(data)

    if mode == 'zero':
        # Zero byte padding
        return data.rstrip(b'\x00')

    elif mode == 'pkcs#5':
        # PKCS#5
        padlen = data[-1]
        return data[:-padlen]
