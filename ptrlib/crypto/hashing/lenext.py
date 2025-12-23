"""Length Extension Attack"""
from typing import Any, Tuple


def lenext(hash_class: Any, padlen: int, known_hash: bytes, known_message: bytes, append_message: bytes) -> Tuple[str, bytes]:
    """Length Extension Attack
    
    Given the value of hash(s + m1), this function calculates
    the value of hash(s + m1 + pad + m2).

    Examples:
        .. code-block:: python

            # md5(SALT + b"Hello") = a67ecc30adca8ee6e70f9c25678f2a9f
            # Given the length of SALT is 5
            p, h = lenext(
                MD5,
                5,
                b"a67ecc30adca8ee6e70f9c25678f2a9f",
                b"Hello",
                b"World",
            )

    Notes:
        The hash class must implement at least:
        ``set_iv(iv)``, ``update(message)``, ``convert(hash)``, and ``padding(data)``.

        Also, an argument which describes the message length before the current blocks
        is given to the constructor of ``hash_class``.
    """
    hash_func = hash_class()

    # Get the last output
    iv = hash_func.convert(known_hash)
    if not iv:
        raise ValueError('The length of `known_hash` is invalid')

    # Set the first data
    data = b'?' * padlen + known_message
    data = hash_func.padding(data)

    # Length extension
    hash_func = hash_class(len(data))
    hash_func.set_iv(iv)
    hash_func.update(append_message)

    return hash_func.hexdigest(), data[padlen:] + append_message
