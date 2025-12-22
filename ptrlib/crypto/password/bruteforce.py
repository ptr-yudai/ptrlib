from itertools import chain, product

def bruteforce(minlen: int | None = None,
               maxlen: int | None = None,
               charset: list[str] | list[bytes] | list[int] | str | bytes | None = None):
    if minlen is None:
        minlen = 1
    if maxlen is None:
        maxlen = minlen

    if minlen <= 0 or maxlen <= 0:
        raise ValueError("Length must be positive integer")
    if maxlen < minlen:
        minlen, maxlen = maxlen, minlen

    if charset and len(charset) == 0:
        raise ValueError("Empty charset")

    if charset is None:
        charset = bytes([i for i in range(0x100)])
    elif isinstance(charset, list):
        if isinstance(charset[0], int):
            charset = bytes(charset)  # type: ignore[arg-type]

    assert isinstance(charset, str) \
        or isinstance(charset, bytes) \
        or isinstance(charset, list)

    for length in range(minlen, maxlen+1):
        for candidate in product(charset, repeat=length):
            if isinstance(charset, bytes):
                # candidate: tuple[int, ...]
                yield bytes(candidate)  # type: ignore[arg-type]
            else:
                if isinstance(candidate[0], bytes):
                    # candidate: tuple[bytes, ...]
                    yield b''.join(candidate)  # type: ignore[arg-type]
                else:
                    # candidate: tuple[str, ...]
                    yield ''.join(candidate)  # type: ignore[arg-type]
