#!/usr/bin/env python
""" Common Modulus Attack """
from ptrlib import *

n = 0x00d91f0102279d099a9aa3a819faefef8e39e71075c5ed59275ae33fd16f10c6b120fbc14f2b0e85b09b7372853c22b359fb4b850e0b66da55585e1221bc23d4a84bc0cce1c1f1c080c74520c3f7cb2d041bc2c372ae96a3b9344dc00b00a75873fd339121804b39b74969ceab850a5ce8c65860fa1e7cfafb052e994a832198ece195ee8bb427a04609b69f052b1d2818741604e2d1fc95008961365f0536f1d3d12b11f3b56f55aa478b18cc5e74918869d9ef8935ce29c66ac5abdde9cc44b8a33c4a3c057624bee9bdfeb8e296798c377110e2209b68fc500d872fd847fe0a7b41c6826b4db3645133a497424b5c111fc661e320b024bccf4b8120847fc92d
e1 = 65537
e2 = 257

m = 0xdeadbeefcafebabe
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
M = common_modulus_attack((c1, c2), (e1, e2), n)

print("plaintext: {}".format(hex(m)))
print("decrypted: {}".format(hex(M)))
