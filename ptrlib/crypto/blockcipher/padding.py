from logging import getLogger

logger = getLogger(__name__)


def pad(data, size, mode='pkcs#5'):
    """Append Padding

    Args:
        data (bytes) : Data to append padding to
        size (int)   : Block size
        mode (str)   : Padding mode

    Available modes:
      zero  : Zero byte padding
      pkcs#5: PKCS#5 Padding
    """
    mode = mode.lower()
    if mode not in ['zero', 'pkcs#5', '']:
        logger.warning("Invalid padding mode. Using 'zero'")
        logger.warning("Choose from zero / pkcs#5 / ")
        mode = 'zero'

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
