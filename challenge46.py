#cryptopals challenge 46

import base64
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

#encrypt msg
msg = int.from_bytes(base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='), 'big')
ct = pow(msg, e, n)

#decode msg
high = n
low = 0
for i in range (n.bit_length()):
    diff = high-low
    change = diff//2
    ct = (pow(2, e, n) * ct) % n
    if (pow(ct, key, n)%2 == 0):
        high -= change
    else:
        low += change
    print(high.to_bytes((high.bit_length() + 7) // 8, byteorder='big'))
    
