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

def str2hex(data):
    """Convert ascii text into hex format"""
    return data.encode("hex")

def str2int(data):
    """Convert ascii text into integer"""
    return int(data.encode("hex"), 16)

def hex2str(data):
    """Convert hex format into ascii text"""
    return data.decode("hex")

def hex2int(data):
    """Convert hex format into integer"""
    return int(data, 16)

def int2str(data):
    """Convert integer into ascii text"""
    return hex(data)[2:].rstrip('L').decode('hex')

def int2hex(data):
    """Convert integer into hex format"""
    return hex(data)[2:].rstrip('L')
