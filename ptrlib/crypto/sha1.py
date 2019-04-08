"""Calculate SHA-1 sum"""
import struct
from ptrlib.util.encoding import *

class SHA1(object):
    """Calcuate SHA-1 sum with the initialization vector specified.
    
    Usage:
        sha1 = SHA1()
        sha1.update("Hello, ")
        sha1.update("World!")
        print(sha1.hexdigest())
    """
    def __init__(self, prevlen=0):
        """Initialize and reset this instance.
        
        You can set the message length of previous blocks.
        """
        self.reset()
        if prevlen > 0:
            self.prevlen = prevlen

    def reset(self):
        """Initialize and reset this instance."""
        self.H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
        self.message = b''
        self.prevlen = 0
        self.sha1sum = None
        self.up2date = False

    def get_iv(self):
        """Get the initialization vector.

        This method returns the vector used as the IV of the next block.
        """
        return self.H

    def set_iv(self, iv):
        """Set the initialization vector.
        
        You can specify the vector used as the IV of the next block.
        """
        if len(iv) != 5:
            raise ValueError("IV must have 5 elements")
        self.H = list(iv)

    def convert(self, hash_string):
        """Convert the given hash into a vector.

        This method returns None if the given hash is not of the MD5 format.
        """
        hash_byte = hash_string
        if len(hash_string) == 40:
            try:
                hash_byte = bytes.fromhex(hash_string)
            except TypeError:
                return False
        elif len(hash_string) != 20:
            return False
        # Convert the given hash into a vector
        return struct.unpack('>IIIII', hash_byte)

    def update(self, message):
        """Update the SHA-1 sum.
        
        This method updates the current SHA-1 sum.
        If you call update(a) and update(b) in this order,
        you will get the SHA-1 sum of a+b.
        """
        if isinstance(message, str):
            message = str2bytes(message)
        self.message += message
        self.up2date = False

    
    def padding(self, message):
        """Append a padding to the given message.

        This method returns the message data with a padding appended.
        """
        # Append a padding
        padlen = 64 - ((len(message) + 8) % 64)
        msglen = (8 * (self.prevlen + len(message))) & 0xffffffffffffffff
        if padlen < 64:
            message += b'\x80' + b'\x00' * (padlen - 1)
        # Append the message length
        message += struct.pack('>Q', msglen)
        return message

    def digest(self):
        """Get the digest of the current SHA-1 sum.

        This method returns the SHA-1 digest of the last updated message.
        """
        if not self.up2date:
            # Calculate the SHA-1 if necessary.
            A, B, C, D, E = self.__calc_sha1()
            self.sha1sum = struct.pack('>IIIII', A, B, C, D, E)
            self.up2date = True
        return self.sha1sum

    def hexdigest(self):
        """Get the hexdigest of the current SHA-1 sum.

        This method returns the SHA-1 digest of the last updated message in hex string.
        """
        return self.digest().hex()

    def __calc_sha1(self):
        """Calculate the SHA-1 sum.

        This method should not be called from outside.
        """
        # Append a padding
        message = self.padding(self.message)
        # Define functions used in the calculation
        NOT = lambda X: X ^ 0xffffffff
        F = [
            lambda B,C,D: (B & C) | (NOT(B) & D),
            lambda B,C,D: B ^ C ^ D,
            lambda B,C,D: (B & C) | (C & D) | (D & B),
            lambda B,C,D: B ^ C ^ D
        ]
        ROT_L = lambda x,n: ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))
        # Prepare the table
        K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]
        # Calculate
        H = list(self.H)
        for i in range(len(message) // 64):
            M = message[i*64:i*64 + 64]
            W = list(struct.unpack('>' + 'I'*16, M))
            for t in range(16, 80):
                W.append(
                    ROT_L(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)
                )
            A, B, C, D, E = H
            for t in range(0, 80):
                ofs = t // 20
                TEMP = ROT_L(A, 5) + F[ofs](B, C, D) + E + W[t] + K[ofs]
                E, D, C, B, A = D, C, ROT_L(B, 30), A, TEMP & 0xFFFFFFFF
            H[0] = (H[0] + A) & 0xFFFFFFFF
            H[1] = (H[1] + B) & 0xFFFFFFFF
            H[2] = (H[2] + C) & 0xFFFFFFFF
            H[3] = (H[3] + D) & 0xFFFFFFFF
            H[4] = (H[4] + E) & 0xFFFFFFFF
        return H

