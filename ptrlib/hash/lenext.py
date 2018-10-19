"""Length Extension Attack"""
import md5
# import sha1
# import sha256
# import sha512
# import crc32

def length_extension(hash_class, padlen, known_hash, known_message, append_message):
    """Length Extension Attack
    
    Given the value of hash(s + m1), this function calculates
    the value of hash(s + m1 + pad + m2).

    Usage:
        # md5(SALT + 'Hello') = a67ecc30adca8ee6e70f9c25678f2a9f
        # Given the length of SALT is 5
        p, h = length_extension(MD5, 5, 'a67ecc30adca8ee6e70f9c25678f2a9f', 'Hello', 'World')
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
        raise ValueError('The length of known_hash is invalid')
    # Set the first data
    data = '?' * padlen + known_message
    data = hash_func.padding(data)
    # Length extension
    hash_func = hash_class(len(data))
    hash_func.set_iv(iv)
    hash_func.update(append_message)
    return hash_func.hexdigest(), data[padlen:] + append_message

if __name__ == '__main__':
    SALT = 'hoge'
    m1 = 'user'
    known_md5 = 'e63f73a0551c84d96fd4d1311410d0ef'
    m2 = "|priv:teacher"
    new_md5, data = length_extension(md5.MD5, len(SALT), known_md5, m1, m2)
    print("known_md5 = " + known_md5)
    print("new_md5   = " + new_md5)
    print("data      = " + repr(data))
