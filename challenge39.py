#cryptopals challenge 39

from Crypto.Util import number
import random
#RSA

#Get greatest common divisor
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

#return modular inverse
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

#random primes
p = number.getPrime(256)
q = number.getPrime(256)

n = p*q
et = (p-1)*(q-1)
e = 17
d = modinv(e, et)

message = b'test'
#convert message to an int for encryption
m = int.from_bytes(b'y\xcc\xa6\xbb', byteorder='little')

#encrypt
c = pow(m,e,n)

#decrypt
decrypt = pow(c,d,n)

assert(decrypt == m)
print(m)
