#!/usr/bin/env python
from ptrlib import *

# Pollard's rho algorithm
#   This method is efficient when the composite consists of two small primes.
#   It takes about a minute to factorize a 96-bit composite.
n = 12960853497408486671
p, q = factorize_pollards_rho(n)
assert n == p * q
print("{0} = {1} * {2}".format(n, p, q))

# Fermat's factorization method
#   This method is efficient when the two primes are close to each other.
n = 63528471527314576896403361642530842023103263634553409208975273668461937758979718473258558434245959885040202983631406268125903788787063745245164958656408942372058993285389896640857233515585397513662661369381176632658549023969177382420947622754817196726670355558212318981395693808869147521576744832366118427563
p, q = factorize_fermat(n)
assert n == p * q
print("{0} = {1} * {2}".format(n, p, q))

