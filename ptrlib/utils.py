"""Utility Package"""
def chunks(data, k, truncate=False):
    """Split a list into chunks

    Split a list into several chunks of size `k`.
    If `truncate` is True and the size of the last chunk is less than `k`,
    the last chunk will be discarded.
    """
    ret = [data[i:i+k] for i in xrange(0, len(data), k)]
    if truncate and len(data) % k:
        ret.pop()
    return ret
