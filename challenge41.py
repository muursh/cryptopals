#cryptopals challenge 40
from Crypto.Util import number
import random

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

#normal RSA setup
p = number.getStrongPrime(768, e=3)
q = number.getStrongPrime(768, e=3)
n = p * q
et = (p-1) * (q-1)
e = 3
d = modinv(e, et)

message = 123

cipher = pow(message, e, n)
rand = random.randint(1, 100000) % n
cp = (pow(rand, e, n) * cipher) % n
pp = pow(cp, d, n)

cracked = (pp * modinv(rand, n)) % n

print(message)
print(cracked)

