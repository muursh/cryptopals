#cryptopals challenge 46

import binascii
import random
from Crypto.Util import number

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No inverse')
    return x%m

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)


#key generation
p = number.getStrongPrime(512, e=3)
q = number.getStrongPrime(512, e=3)
n = p * q
et = (p-1) * (q-1)
e = 3
key = modinv(e, et)

#encrypt message
msg = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==".decode('base64')     
ct = pow(msg, e, n)

