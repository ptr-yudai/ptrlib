"""RSA Class"""
import random

class RSA(object):
    """RSA encryption and decryption
    
    Usage:
        rsa = RSA(p = 3259, 101)
    """
    def __init__(self, n=None, p=None, q=None):
        """Initialize and reset this instance.
        
        n   : p * q
        p, q: Prime numbers
        """
        self.n = n
        self.p = p
        self.q = q
