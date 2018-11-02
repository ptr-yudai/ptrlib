"""Padding Oracle Attack on CBC encryption"""
def padding_oracle_cbc(decrypt, cipher, bs, unknown='\x00', unpad=True):
    """Padding Oracle Attack
    
    Given a ciphersystem such that:
    - The padding follows the format of PKCS7
    - The mode of the block cipher is CBC
    - We can check if the padding of a given cipher is correct
    - We can try to decrypt ciphertexts without limit
    we can break the ciphertext with Padding Oracle Attack.

    Usage:
        plain = padding_oracle_cbc(decrypt, cipher, bs, unknown, unpad)

    The function decrypt must receive ciphertext and return True or False:
        True when the given cipher could successfully be decrypted (No padding error)
        False when the given cipher cannot be decrypted (Padding error detected)
    """
    if len(cipher) % bs != 0:
        raise ValueError("The length of `cipher` must be a multiple of `bs`")
    # Split ciphertext into blocks
    cipher_blocks = []
    for i in xrange(0, len(cipher), bs):
        cipher_blocks.append(cipher[i:i + bs])
    plain_blocks = [None for i in range(len(cipher_blocks))]
    # Break the cipher
    for k in xrange(len(cipher_blocks) - 1, 0, -1):
        plain = ['\x00' for i in range(bs)]
        prev_block = ['\x00' for i in range(bs)]
        for n in xrange(1, bs + 1):
            for c in xrange(0x100):
                prev_block[-n] = chr(c)
                data = ''.join(prev_block) + cipher_blocks[k]
                ret = decrypt(data)
                if ret == True:
                    plain[-n] = chr(n ^ ord(cipher_blocks[k-1][-n]) ^ c)
                    for i in xrange(bs):
                        prev_block[i] = chr((n+1) ^ ord(plain[i]) ^ ord(cipher_blocks[k-1][i]))
                    break
                elif ret != False:
                    raise ValueError("The function `decrypt` must return True or False")
        plain_blocks[k] = ''.join(plain)
    plain_blocks[0] = unknown * bs
    return ''.join(plain_blocks)
