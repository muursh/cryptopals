#cryptopals challenge 43

from Crypto.Random import random
from Crypto.Util.number import getPrime
import binascii
import hashlib

def egcd(a, b):
    if b == 0:
        return (1, 0)
    else:
        q = a // b;
        r = a % b;
        (s, t) = egcd(b, r)
        return (t, s - q * t)

def invmod(a, N):
    (x, y) = egcd(a, N)
    return x % N
