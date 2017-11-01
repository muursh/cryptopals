#cryptopals challenge 40

from Crypto.Util import number
import random
from functools import reduce

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m


def CRT(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)

    for n_i, a_i, in zip(n, a):
        p = prod / n_i
        sum += a_i * modinv(p, n_i) * p
    return sum % prod


def attack(keys, messages):
    result = CRT(messages, keys)
    return pow(result, 1/3.0)


def mod(size, e):
    p = e+1
    q = e+1
    while ((p%e) == 1):
        p = number.getPrime(100)
    while ((q%e) == 1):
        q = number.getPrime(100)
    return p*q

#test chinese remainder - test values from wikipedia
n = [3, 5, 7]
a = [2, 3, 2]
assert (CRT(n, a) == 23.0)

keys = [mod(1024, 3), mod(1024,3), mod(1024,3)]
mess = [pow(0x1, 3, 2), pow(0x1, 3, 2), pow(0x1, 3, 2)]
rec = attack(keys, mess)
