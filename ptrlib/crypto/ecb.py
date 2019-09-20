from logging import getLogger

logger = getLogger(__name__)


def ecb_chosenplaintext(encryptor, prefix, plaintext_length, *, bs=16, unknown=b"?"):
    """Chosen Plaintext Attack to ECB Mode Cryptography
    TODO: implement postfix
    """
    plaintext = b""
    for i in range(plaintext_length):
        # calculate padding size
        padsize = bs - (len(prefix + plaintext) % bs) - 1
        padding = unknown * padsize

        found = False
        for b in range(256):
            # build payload
            payload = (
                padding
                + plaintext
                + bytes([b])
                + (prefix + padding)[-(bs - 1) + (len(plaintext) % bs) :]
            )

            # get result
            result = encryptor(payload)

            # check if two blocks are same
            bi = len(prefix + padding + plaintext) // bs
            bi2 = (len(prefix + payload + plaintext) - 1) // bs
            if result[bi * bs : (bi + 1) * bs] == result[bi2 * bs : (bi2 + 1) * bs]:
                found = True
                plaintext += bytes([b])
                break
        logger.info(
            "decrypted {}. current plaintext: {}".format(
                repr(chr(plaintext[-1])), repr(plaintext)
            )
        )
        assert found
    return plaintext
