"""Calculate MD5 sum."""
import struct
from ptrlib.util.encoding import *

class MD5(object):
    """Calculate MD5 sum with the initialization vector specified.
    
    Usage:
        md5 = MD5()
        md5.update("Hello, ")
        md5.update("World!")
        print(md5.hexdigest())
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
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476
        self.md5sum = None
        self.message = b''
        self.prevlen = 0
        self.up2date = False

    def get_iv(self):
        """Get the initialization vector.

        This method returns the vector used as the IV of the next block.
        """
        return (self.A, self.B, self.C, self.D)

    def set_iv(self, iv):
        """Set the initialization vector.
        
        You can specify the vector used as the IV of the next block.
        """
        self.A, self.B, self.C, self.D = list(iv)

    def convert(self, hash_string):
        """Convert the given hash into a vector.

        This method returns None if the given hash is not of the MD5 format.
        """
        hash_byte = hash_string
        if len(hash_string) == 32:
            try:
                hash_byte = bytes.fromhex(hash_string)
            except TypeError:
                return False
        elif len(hash_string) != 16:
            return False
        # Convert the given hash into a vector
        return struct.unpack('<IIII', hash_byte)

    def update(self, message):
        """Update the MD5 sum.
        
        This method updates the current MD5 sum.
        If you call update(a) and update(b) in this order,
        you will get the MD5 sum of a+b.
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
        msglen = (8 * (self.prevlen + len(message))) % 18446744073709551616
        if padlen < 64:
            message += b'\x80' + b'\x00' * (padlen - 1)
        # Append the message length
        message += struct.pack('<Q', msglen)
        return message
    
    def digest(self):
        """Get the digest of the current MD5 sum.

        This method returns the MD5 digest of the last updated message.
        """
        if not self.up2date:
            # Calculate the MD5 if necessary.
            A, B, C, D = self.__calc_md5()
            self.md5sum = struct.pack('<IIII', A, B, C, D)
            self.up2date = True
        return self.md5sum

    def hexdigest(self):
        """Get the hexdigest of the current MD5 sum.

        This method returns the MD5 digest of the last update message in hex string.
        """
        return self.digest().hex()

    def __calc_md5(self):
        """Calculate the MD5 sum.

        This method should not be called outside.
        """
        # Append a padding
        message = self.padding(self.message)
        # Define functions used in the calculation
        NOT = lambda X: X ^ 0xffffffff
        F = lambda X,Y,Z: (X & Y) | (NOT(X) & Z)
        G = lambda X,Y,Z: (X & Z) | (Y & NOT(Z))
        H = lambda X,Y,Z: X ^ Y ^ Z
        I = lambda X,Y,Z: Y ^ (X | NOT(Z))
        ROT_L = lambda x,n: (x << n) | (x >> (32 - n))
        OPE = lambda BOX,a,b,c,d,k,s,i: (b + (
            ROT_L(
                (a + BOX(b,c,d) + X[k] + T[i-1]) & 0xffffffff, s
            ) & 0xffffffff
        )) & 0xffffffff
        # Prepare the table
        T = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        ]
        # Calculate
        A, B, C, D = self.A, self.B, self.C, self.D
        for i in range(len(message) // 64):
            M = message[i*64:i*64 + 64]
            X = []
            for j in range(16):
                X.append(struct.unpack('<I', M[j*4:j*4 + 4])[0])
            AA, BB, CC, DD = A, B, C, D
            # Round 1
            A = OPE(F, A, B, C, D, 0, 7, 1)
            D = OPE(F, D, A, B, C, 1, 12, 2)
            C = OPE(F, C, D, A, B, 2, 17, 3)
            B = OPE(F, B, C, D, A, 3, 22, 4)
            A = OPE(F, A, B, C, D, 4, 7, 5)
            D = OPE(F, D, A, B, C, 5, 12, 6)
            C = OPE(F, C, D, A, B, 6, 17, 7)
            B = OPE(F, B, C, D, A, 7, 22, 8)
            A = OPE(F, A, B, C, D, 8, 7, 9)
            D = OPE(F, D, A, B, C, 9, 12, 10)
            C = OPE(F, C, D, A, B, 10, 17, 11)
            B = OPE(F, B, C, D, A, 11, 22, 12)
            A = OPE(F, A, B, C, D, 12, 7, 13)
            D = OPE(F, D, A, B, C, 13, 12, 14)
            C = OPE(F, C, D, A, B, 14, 17, 15)
            B = OPE(F, B, C, D, A, 15, 22, 16)
            # Round 2
            A = OPE(G, A, B, C, D, 1, 5, 17)
            D = OPE(G, D, A, B, C, 6, 9, 18)
            C = OPE(G, C, D, A, B, 11, 14, 19)
            B = OPE(G, B, C, D, A, 0, 20, 20)
            A = OPE(G, A, B, C, D, 5, 5, 21)
            D = OPE(G, D, A, B, C, 10, 9, 22)
            C = OPE(G, C, D, A, B, 15, 14, 23)
            B = OPE(G, B, C, D, A, 4, 20, 24)
            A = OPE(G, A, B, C, D, 9, 5, 25)
            D = OPE(G, D, A, B, C, 14, 9, 26)
            C = OPE(G, C, D, A, B, 3, 14, 27)
            B = OPE(G, B, C, D, A, 8, 20, 28)
            A = OPE(G, A, B, C, D, 13, 5, 29)
            D = OPE(G, D, A, B, C, 2, 9, 30)
            C = OPE(G, C, D, A, B, 7, 14, 31)
            B = OPE(G, B, C, D, A, 12, 20, 32)
            # Round 3
            A = OPE(H, A, B, C, D, 5, 4, 33)
            D = OPE(H, D, A, B, C, 8, 11, 34)
            C = OPE(H, C, D, A, B, 11, 16, 35)
            B = OPE(H, B, C, D, A, 14, 23, 36)
            A = OPE(H, A, B, C, D, 1, 4, 37)
            D = OPE(H, D, A, B, C, 4, 11, 38)
            C = OPE(H, C, D, A, B, 7, 16, 39)
            B = OPE(H, B, C, D, A, 10, 23, 40)
            A = OPE(H, A, B, C, D, 13, 4, 41)
            D = OPE(H, D, A, B, C, 0, 11, 42)
            C = OPE(H, C, D, A, B, 3, 16, 43)
            B = OPE(H, B, C, D, A, 6, 23, 44)
            A = OPE(H, A, B, C, D, 9, 4, 45)
            D = OPE(H, D, A, B, C, 12, 11, 46)
            C = OPE(H, C, D, A, B, 15, 16, 47)
            B = OPE(H, B, C, D, A, 2, 23, 48)
            # Round 4
            A = OPE(I, A, B, C, D, 0, 6, 49)
            D = OPE(I, D, A, B, C, 7, 10, 50)
            C = OPE(I, C, D, A, B, 14, 15, 51)
            B = OPE(I, B, C, D, A, 5, 21, 52)
            A = OPE(I, A, B, C, D, 12, 6, 53)
            D = OPE(I, D, A, B, C, 3, 10, 54)
            C = OPE(I, C, D, A, B, 10, 15, 55)
            B = OPE(I, B, C, D, A, 1, 21, 56)
            A = OPE(I, A, B, C, D, 8, 6, 57)
            D = OPE(I, D, A, B, C, 15, 10, 58)
            C = OPE(I, C, D, A, B, 6, 15, 59)
            B = OPE(I, B, C, D, A, 13, 21, 60)
            A = OPE(I, A, B, C, D, 4, 6, 61)
            D = OPE(I, D, A, B, C, 11, 10, 62)
            C = OPE(I, C, D, A, B, 2, 15, 63)
            B = OPE(I, B, C, D, A, 9, 21, 64)
            # Update the vector
            A = (A + AA) % 4294967296
            B = (B + BB) % 4294967296
            C = (C + CC) % 4294967296
            D = (D + DD) % 4294967296
        # Return the result
        return A, B, C, D
