"""Length Extension Attack"""
from ptrlib.crypto.md5 import MD5
# import sha1
# import sha256
# import sha512

def lenext(hash_class, padlen, known_hash, known_message, append_message):
    """Length Extension Attack
    
    Given the value of hash(s + m1), this function calculates
    the value of hash(s + m1 + pad + m2).

    Usage:
        # md5(SALT + 'Hello') = a67ecc30adca8ee6e70f9c25678f2a9f
        # Given the length of SALT is 5
        p, h = lenext(MD5, 5, 'a67ecc30adca8ee6e70f9c25678f2a9f', 'Hello', 'World')
        # md5(SALT + 'Hello' + )

    The hashfunc must have the following methods:
        set_iv(iv), update(message), convert(hash), padding(data)
    Also, an argument which describes the message length before the current blocks
    is given to the construntor of hash_class.
    """
    hash_func = hash_class()

    # Get the last output
    iv = hash_func.convert(known_hash)
    if iv is None:
        raise ValueError('The length of `known_hash` is invalid')

    # Set the first data
    data = b'?' * padlen + known_message
    data = hash_func.padding(data)

    # Length extension
    hash_func = hash_class(len(data))
    hash_func.set_iv(iv)
    hash_func.update(append_message)
    return hash_func.hexdigest(), data[padlen:] + append_message
