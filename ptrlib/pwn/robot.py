from ptrlib.util.packing import *

class Robot(object):
    """Dynamically find function in loaded libc
    """
    def __init__(self, leak, base=None, elf=None):
        """Activate robot
        
        Args:
            leak (function): 
            base (int)     : 
            elf (ELF)      : 
        """
        self._proc_base = base
        self._libc_base = None
        self.elf = elf
        self.internal_leak = leak

        if self.elf and not self.elf.pie():
            self._proc_base = 0

        # Assertion
        """
        if self.leak(self.proc_base, 4) != b'\x7fELF':
            logger.warn("proc base or leak function is wrong")
        else:
            logger.info("proc base is correct")
        """

    def leak(self, address, size):
        """Leak data 
        Leak `size`-byte data located at `address`
        
        Args:
            address (int): Address to leak
            size (int)   : Size of leak
        """
        output = b''
        for i in range(size):
            r = self.internal_leak(address + len(output))
            if len(r) == 0:
                logger.warn("`leak` is not working!")
                return None
            output += r
            if len(output) >= size:
                break
        return output[:size]
    
    def libc(self):
        """ Find libc base """
        if self.elf is None:
            # [TODO]
            raise NotImplementedError("Currently requires the target binary.")
        else:
            pass
        return

    def resolve(self, symb):
        return self.lookup(symb)

    def lookup(self, symb, base):
        """ Find a symbol by name
        
        Args:
            symb (int): Symbol name
            base (int): Base address of the library
        """
        logger.warn("Not implemented yet!")
        return None

    def find_base(self, address, delta=0):
        """ Find base address
        
        Args:
            address (int): Address of data in the target binary
            delta (int)  : Possible (min) offset from base to the address
        """
        pagesize = 0x1000
        ptr = (address - delta) & ~(pagesize - 1)

        while True:
            first = self.leak(ptr, 1)
            if first == b'\x7f':
                leaked = self.leak(ptr + 1, 3)
                logger.debug("@{}: {}".format(hex(ptr), first + leaked))
                if leaked == b'ELF':
                    logger.debug("Found base address: {}".format(hex(ptr)))
                    break
            
            ptr -= pagesize
            if ptr < 0:
                logger.warn("Out of memory. Could not find base address.")
                return None
        
        return ptr
