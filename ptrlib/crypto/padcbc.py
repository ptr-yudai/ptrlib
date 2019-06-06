from logging import getLogger
from ptrlib.util.encoding import *

logger = getLogger(__name__)

def padding_oracle_block(decrypt, prev_block, cipher_block, bs):
    plain = [b"\x00" for i in range(bs)]

    for i in range(bs):
        found = False
        for b in range(256):
            dummy_block = b"\x00" * (bs - i - 1) + bytes([b])
            for b2 in plain[bs - i :]:
                dummy_block += bytes([b2[0] ^ (i + 1) ^ prev_block[len(dummy_block)]])

            ret = decrypt(dummy_block + cipher_block)
            if ret is True:
                plain[bs - i - 1] = bytes([b ^ (i + 1) ^ prev_block[bs - i - 1]])
                logger.info(
                    "decrypted a byte {}/{}: {}".format(i + 1, bs, plain[bs - i - 1]))

                found = True
                break
            elif ret is not False:
                raise ValueError("The function `decrypt` must return True or False")
        assert found
    return b"".join(plain)


"""Padding Oracle Attack on CBC encryption"""


def padding_oracle(decrypt, cipher, *, bs, unknown=b"\x00", iv=None):
    """Padding Oracle Attack

    Given a ciphersystem such that:
    - The padding follows the format of PKCS7
    - The mode of the block cipher is CBC
    - We can check if the padding of a given cipher is correct
    - We can try to decrypt ciphertexts without limit
    we can break the ciphertext with Padding Oracle Attack.

    Usage:
        plain = padding_oracle(decrypt, cipher, bs, unknown)

    The function decrypt must receive ciphertext and return True or False:
        True when the given cipher could successfully be decrypted (No padding error)
        False when the given cipher cannot be decrypted (Padding error detected)
    """
    if len(cipher) % bs != 0:
        raise ValueError("The length of `cipher` must be a multiple of `bs`")

    # Split ciphertext into blocks
    cipher_blocks = []
    for i in range(0, len(cipher), bs):
        cipher_blocks.append(cipher[i : i + bs])
    plain_blocks = [None for i in range(len(cipher_blocks))]

    # Break the cipher
    for k in range(len(cipher_blocks) - 1, 0, -1):
        plain_blocks[k] = padding_oracle_block(
            decrypt, cipher_blocks[k - 1], cipher_blocks[k], bs
        )
        logger.info(
            "decrypted a block {}/{}: {}".format(
                len(cipher_blocks) - k + 1, len(cipher_blocks), plain_blocks[k]
            )        )

    if isinstance(unknown, str):
        unknown = str2bytes(unknown)

    if iv:
        plain_blocks[0] = padding_oracle_block(decrypt, iv, cipher_blocks[0], bs)
        logger.info("decrypted an iv block: {}".format(plain_blocks[0]))
    else:
        plain_blocks[0] = unknown * bs

    return b"".join(plain_blocks)


"""Padding Oracle Enctyption Attack on CBC encryption"""


def padding_oracle_encrypt(decrypt, plain, *, bs, unknown=b"\x00"):
    """Padding Oracle Encryption Attack

    Usage:
        iv, cipher = padding_oracle_encrypt(decrypt, plain, bs, unknown)
    """
    if len(plain) % bs != 0:
        raise ValueError("The length of `plain` must be a multiple of `bs`")

    cipher_blocks = [unknown * bs for _ in range(len(plain) // bs + 1)]

    for k in range(len(cipher_blocks) - 1, 0, -1):
        cipher_block = bytearray(
            padding_oracle_block(decrypt, cipher_blocks[k - 1], cipher_blocks[k], bs)
        )
        for i in range(bs):
            cipher_block[i] = cipher_block[i] ^ ord(unknown) ^ plain[bs * (k - 1) + i]
        cipher_blocks[k - 1] = cipher_block
        logger.info(
            "encrypted a block {}/{}: {}".format(
                len(cipher_blocks) - k + 1, len(cipher_blocks), cipher_blocks[k - 1]
            ))

    return bytes(cipher_blocks[0]), b"".join(cipher_blocks[1:])
