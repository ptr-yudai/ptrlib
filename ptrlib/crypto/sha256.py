"""Calculate SHA-256 sum"""
import struct
from ptrlib.util.encoding import *

class SHA256(object):
    """Calculate SHA-256 sum with the initialization vector specified.
    
    Usage:
        sha256 = SHA256()
        sha256.update("Hello, ")
        sha256.update("World!")
        print(sha256.hexdigest())
    """
    def __init__(self, prevlen=0):
        """Initialize and reset this instance.

        You can set the message length of the previuos blocks.
        """
        self.reset()
        if prevlen > 0:
            self.prevlen = prevlen

    def reset(self):
        """Initialize and reset this instance."""
        self.H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        self.message = b''
        self.prevlen = 0
        self.sha256sum = None
        self.up2date = False

    def get_iv(self):
        """Get the initialization vector.
        
        This method returns the vector used as the IV of the next block.
        """
        return self.H

    def set_iv(self, iv):
        """Set the initialization vector.

        You can change the vector used as the IV of the next block.
        """
        if len(iv) != 8:
            raise ValueError("IV must have 8 elements")
        self.H = list(iv)

    def convert(self, hash_string):
        """Convert the given hash into a vector.

        This method returns None if the given hash is not of the MD5 format.
        """
        hash_byte = hash_string
        if len(hash_string) == 64:
            try:
                hash_byte = bytes.fromhex(hash_string)
            except TypeError:
                return False
        elif len(hash_string) != 32:
            return False
        return struct.unpack('>IIIIIIII', hash_byte)
        
    def update(self, message):
        """Update the SHA-256 sum.

        This method updates the current SHA-256 sum.
        If you call update(a) and update(b) in this order,
        yuo will get the SHA-256 sum of a+b.
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
        """Get the digest of the current SHA-256 sum.

        This method returns the SHA-256 digest of the last updated message.
        """
        if not self.up2date:
            # Calculate the SHA-256 if necessary.
            A, B, C, D, E, F, G, H = self.__calc_sha256()
            self.sha256sum = struct.pack('>IIIIIIII', A, B, C, D, E, F, G, H)
            self.up2date = True
        return self.sha256sum

    def hexdigest(self):
        """Get the hexdigest of the current SHA-256 sum.

        This method returns the SHA-256 digest of the last updated message in hex string.
        """
        return self.digest().hex()

    def __mod_add(self, input_list):
        val = 0
        for x in input_list:
            val += x
        return val % 0x100000000

    def __calc_sha256(self):
        """Calculate the SHA-256 sum.

        This method should not be called from outside.
        """
        # Append a padding
        message = self.padding(self.message)
        # Define functions used in the calculation
        SHR = lambda v, n: (v & 0xffffffff) >> n
        ROTR = lambda v, n: ((v & 0xffffffff) >> (n & 31)) | (v << (32 - (n & 31))) & 0xffffffff
        CHOOSE = lambda x, y, z: z ^ (x & (y ^ z))
        MAJORITY = lambda x, y, z: ((x | y) & z) | (x & y)
        SIGMA0 = lambda x: ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)
        SIGMA1 = lambda x: ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)
        GAMMA0 = lambda x: ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)
        GAMMA1 = lambda x: ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)
        # Prepare the table
        K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        Hash = list(self.H)
        # Process
        for j in range(len(message) // 64):
            A, B, C, D, E, F, G, H = Hash
            blocks = [message[j*64 + i:j*64 + i+4] for i in range(0, 64, 4)]
            w = []
            # Rotation
            for i in range(64):
                if i <= 15:
                    w.append(struct.unpack('>I', blocks[i])[0])
                else:
                    w.append(self.__mod_add((
                        GAMMA1(w[i - 2]), w[i - 7],
                        GAMMA0(w[i - 15]), w[i - 16]
                    )))
                t1 = self.__mod_add((
                    H, SIGMA1(E), CHOOSE(E, F, G), K[i], w[i]
                ))
                t2 = self.__mod_add((
                    SIGMA0(A), MAJORITY(A, B, C)
                ))
                H, G, F, E = G, F, E, self.__mod_add((D, t1))
                D, C, B, A = C, B, A, self.__mod_add((t1, t2))
            # Update
            Hash = [
                self.__mod_add((Hash[0], A)),
                self.__mod_add((Hash[1], B)),
                self.__mod_add((Hash[2], C)),
                self.__mod_add((Hash[3], D)),
                self.__mod_add((Hash[4], E)),
                self.__mod_add((Hash[5], F)),
                self.__mod_add((Hash[6], G)),
                self.__mod_add((Hash[7], H))
            ]
        return Hash
